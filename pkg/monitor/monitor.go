package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/api"
	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/discovery"
	"github.com/nodexeus/sqd-agent/pkg/grafana"
	"github.com/nodexeus/sqd-agent/pkg/vectorconfig"
	log "github.com/sirupsen/logrus"
)

// NodeStatus represents the combined local and network status of a node
// NodeRestartInfo stores information about node restarts
type NodeRestartInfo struct {
	LastRestart  time.Time `json:"last_restart"`
	RestartCount int       `json:"restart_count"`
}

// RestartHistory stores restart information for all nodes
type RestartHistory struct {
	Nodes map[string]NodeRestartInfo `json:"nodes"`
}

type NodeStatus struct {
	Instance          string
	PeerID            string
	Name              string
	LocalName         string // Local name of the node (from the instance list)
	LocalIp           string // Local IP of the node (from the instance list)
	ImageVersion      string // Image version of the node (from the instance list)
	LocalStatus       string
	NetworkStatus     string // For special statuses like "pending" for newly created nodes
	APR               float64
	Online            bool
	Jailed            bool
	JailReason        string
	Queries24Hours    int64
	Uptime24Hours     float64
	Version           string
	ServedData24Hours int64
	StoredData        int64
	TotalDelegation   int64
	ClaimedReward     int64
	ClaimableReward   int64
	CreatedAt         time.Time
	LastChecked       time.Time
	LastRestart       time.Time
	RestartStartTime  time.Time // When the current restart was initiated
	RestartCount      int       // Count restarts for better tracking
	Healthy           bool
}

// Monitor is responsible for monitoring SQD nodes
type Monitor struct {
	config                *config.Config
	discoverer            *discovery.Discoverer
	apiClient             *api.GraphQLClient
	nodes                 map[string]*NodeStatus // Map of instance name to node status
	notifiers             []Notifier
	metricsExporter       MetricsExporter
	restartHistory        *RestartHistory
	vectorConfig          *vectorconfig.VectorConfig
	restartHistoryDirty   bool
	lastRestartHistorySave time.Time
	hostname              string
}

// getRestartHistoryPath returns the path to the restart history file
func getRestartHistoryPath() string {
	// Use /var/lib/sqd-agent directory for persistence
	dataDir := "/var/lib/sqd-agent"

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Warnf("Failed to create data directory: %v", err)
		// Fallback to temp directory
		return filepath.Join(os.TempDir(), "sqd-agent-restart-history.json")
	}

	return filepath.Join(dataDir, "restart-history.json")
}

// saveRestartHistoryToDisk persists the restart history to disk immediately
func saveRestartHistoryToDisk(history *RestartHistory) error {
	filePath := getRestartHistoryPath()

	// Marshal the history to JSON
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal restart history: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write restart history file: %w", err)
	}

	log.Debugf("Saved restart history to %s", filePath)
	return nil
}

// saveRestartHistory marks the restart history as dirty and saves it if needed
func (m *Monitor) saveRestartHistory() error {
	m.restartHistoryDirty = true
	
	// Save immediately if it's been more than 5 minutes since last save
	if time.Since(m.lastRestartHistorySave) > 5*time.Minute {
		return m.flushRestartHistory()
	}
	
	return nil
}

// flushRestartHistory immediately saves the restart history to disk
func (m *Monitor) flushRestartHistory() error {
	if !m.restartHistoryDirty {
		return nil // No changes to save
	}
	
	if err := saveRestartHistoryToDisk(m.restartHistory); err != nil {
		return err
	}
	
	m.restartHistoryDirty = false
	m.lastRestartHistorySave = time.Now()
	return nil
}

// loadRestartHistory loads the restart history from disk
func loadRestartHistory() (*RestartHistory, error) {
	filePath := getRestartHistoryPath()

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Info("No restart history file found, starting with empty history")
		return &RestartHistory{Nodes: make(map[string]NodeRestartInfo)}, nil
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read restart history file: %w", err)
	}

	// Unmarshal JSON
	var history RestartHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("failed to parse restart history: %w", err)
	}

	if history.Nodes == nil {
		history.Nodes = make(map[string]NodeRestartInfo)
	}

	log.Infof("Loaded restart history for %d nodes from %s", len(history.Nodes), filePath)
	return &history, nil
}

// Notifier is an interface for notification handlers
type Notifier interface {
	NotifyNodeRestartAttempt(node *NodeStatus, unhealthyReason string) error
	NotifyNodeRestartSuccess(node *NodeStatus, unhealthyReason string) error
	NotifyNodeRestartFailure(node *NodeStatus, unhealthyReason string, err error) error
}

// MetricsExporter is an interface for metrics exporters
type MetricsExporter interface {
	UpdateMetrics()
}

// NewMonitor creates a new node monitor
func NewMonitor(config *config.Config, discoverer *discovery.Discoverer, apiClient *api.GraphQLClient, hostname string) *Monitor {
	// Load restart history from persistent storage
	history, err := loadRestartHistory()
	if err != nil {
		log.Warnf("Failed to load restart history: %v", err)
		history = &RestartHistory{Nodes: make(map[string]NodeRestartInfo)}
	}

	return &Monitor{
		config:                config,
		discoverer:            discoverer,
		apiClient:             apiClient,
		nodes:                 make(map[string]*NodeStatus),
		notifiers:             make([]Notifier, 0),
		metricsExporter:       nil,
		restartHistory:        history,
		restartHistoryDirty:   false,
		lastRestartHistorySave: time.Now(),
		hostname:              hostname,
	}
}

// AddNotifier adds a notifier to the monitor
func (m *Monitor) AddNotifier(notifier Notifier) {
	m.notifiers = append(m.notifiers, notifier)
}

// SetMetricsExporter sets the metrics exporter for the monitor
func (m *Monitor) SetMetricsExporter(exporter MetricsExporter) {
	m.metricsExporter = exporter
}

// Start starts the monitoring process
func (m *Monitor) Start(ctx context.Context) error {
	// Initial discovery and check
	if err := m.discoverAndCheck(ctx); err != nil {
		// Log the error but continue instead of failing
		log.Warnf("Initial node discovery failed: %v", err)
		log.Info("Agent will continue to run and retry on next monitor period")
	}


	// Start periodic monitoring
	log.Infof("Starting tickers - Monitor period: %s, Action period: %s", m.config.MonitorPeriod, m.config.ActionPeriod)
	monitorTicker := time.NewTicker(m.config.MonitorPeriod)
	// Action ticker should run frequently to check for restart eligibility, not wait for the full action period
	actionTicker := time.NewTicker(m.config.MonitorPeriod)
	log.Infof("Both tickers set to run every %s", m.config.MonitorPeriod)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("Monitor goroutine panic recovered: %v", r)
				// Optionally restart the goroutine or take other recovery actions
			}
		}()
		for {
			select {
			case <-ctx.Done():
				monitorTicker.Stop()
				actionTicker.Stop()
				return
			case <-monitorTicker.C:
				if err := m.discoverAndCheck(ctx); err != nil {
					log.Errorf("Error during node discovery and check: %v", err)
				}
			case <-actionTicker.C:
				// Always run actions, but pass the passive mode flag
				log.Infof("Action ticker fired - calling takeActions with passiveMode=%t", m.config.PassiveMode)
				if err := m.takeActions(ctx, m.config.PassiveMode); err != nil {
					log.Errorf("Error taking actions on nodes: %v", err)
				}
			}
		}
	}()

	return nil
}

// updateVectorConfig updates the Vector configuration with the current node statuses
func (m *Monitor) updateVectorConfig(ctx context.Context) error {
	nodeInfos := make([]vectorconfig.NodeInfo, 0, len(m.nodes))
	for _, node := range m.nodes {
		// Use the local name for the node if available, fall back to Name
		nodeIp := node.LocalIp

		nodeInfos = append(nodeInfos, vectorconfig.NodeInfo{
			Ip: nodeIp,
		})
	}

	if err := vectorconfig.GenerateConfig(ctx, nodeInfos); err != nil {
		return fmt.Errorf("failed to update Vector config: %w", err)
	}
	return nil
}

// discoverAndCheck discovers nodes and checks their status
func (m *Monitor) discoverAndCheck(ctx context.Context) error {
	log.Debug("Starting discoverAndCheck")

	// Discover nodes
	nodes, err := m.discoverer.DiscoverNodes()
	if err != nil {
		return fmt.Errorf("failed to discover nodes: %w", err)
	}

	log.Debugf("Discovered %d nodes", len(nodes))

	// Get network status for each node
	networkStatuses := make(map[string]*api.NodeNetworkStatus)

	// Test GraphQL API connection if not connected
	if !m.apiClient.IsConnected() {
		log.Debug("GraphQL API connection not established, testing connection...")
		if !m.apiClient.TestConnection(ctx) {
			log.Warnf("GraphQL API connection is down. Last error: %v (occurred %s ago)",
				m.apiClient.GetLastError(),
				time.Since(m.apiClient.GetLastErrorTime()).Round(time.Second))
			log.Info("Will continue with local status only and retry connection on next check")
		} else {
			log.Info("Successfully established connection to GraphQL API")
		}
	}

	// If we have a connection, fetch network status
	if m.apiClient.IsConnected() {
		log.Debug("GraphQL API is connected, fetching network status for discovered nodes")
		for _, node := range nodes {
			if node.PeerID == "" {
				log.Debugf("Skipping network status for node %s: no peer ID", node.Instance)
				continue
			}

			log.Debugf("Fetching network status for node %s with peer ID %s", node.Instance, node.PeerID)
			status, err := m.apiClient.GetNodeStatus(ctx, node.PeerID)
			if err != nil {
				log.Errorf("Failed to get network status for node %s: %v", node.Instance, err)
				// If we get an error, mark the connection as down and break the loop
				if !m.apiClient.IsConnected() {
					log.Warn("GraphQL API connection lost, will retry on next check")
					break
				}
				continue
			}
			if status.Name == "" {
				log.Debugf("Node %s has no name, likely unregistered", node.Instance)
				continue
			}

			log.Debugf("Successfully retrieved network status for node %s: online=%v, jailed=%v, jailReason=%s, name=%s, apr=%f, peerID=%s, version=%s, claimedReward=%d, claimableReward=%d, servedData24Hours=%d, storedData=%d, totalDelegation=%d, uptime24Hours=%f, queries24Hours=%d",
				node.Instance, status.Online, status.Jailed, status.JailReason, status.Name, status.APR, status.PeerID, status.Version, status.ClaimedReward, status.ClaimableReward, status.ServedData24Hours, status.StoredData, status.TotalDelegation, status.Uptime24Hours, status.Queries24Hours)

			networkStatuses[node.PeerID] = status
		}

		if len(networkStatuses) == 0 && len(nodes) > 0 {
			log.Warnf("Failed to get network status for any nodes")
			if !m.apiClient.IsConnected() {
				log.Warnf("GraphQL API connection is down. Last error: %v (occurred %s ago)",
					m.apiClient.GetLastError(),
					time.Since(m.apiClient.GetLastErrorTime()).Round(time.Second))
				log.Info("Will continue with local status only and retry connection on next check")
			}
		}
	}

	// Create a map to track which nodes we've seen in this discovery
	discoveredInstances := make(map[string]bool)
	for _, node := range nodes {
		discoveredInstances[node.Instance] = true
	}

	// Prepare all updates
	updates := make(map[string]*NodeStatus)
	unhealthyNodes := make(map[string]string) // instance -> reason

	for _, node := range nodes {
		// Get or create node status
		status := &NodeStatus{
			Instance:     node.Instance,
			PeerID:       node.PeerID,
			Name:         node.Name,
			LocalName:    node.LocalName, // Set the local name from the discovered node
			LocalIp:      node.LocalIp,   // Set the local IP from the discovered node
			ImageVersion: node.ImageVersion,
			Version:      node.Version,
			LastChecked:  time.Now(),
		}

		// Update local status
		status.LocalStatus = node.LocalStatus
		status.PeerID = node.PeerID

		// If we have network status for this node, update the status with the network data
		if node.PeerID != "" {
			if networkStatus, ok := networkStatuses[node.PeerID]; ok {
				// Update status with network data
				status.Name = networkStatus.Name
				status.APR = networkStatus.APR
				status.Online = networkStatus.Online
				status.Jailed = networkStatus.Jailed
				status.JailReason = networkStatus.JailReason
				status.Queries24Hours = networkStatus.Queries24Hours
				status.Uptime24Hours = networkStatus.Uptime24Hours
				status.Version = networkStatus.Version
				status.ServedData24Hours = networkStatus.ServedData24Hours
				status.StoredData = networkStatus.StoredData
				status.TotalDelegation = networkStatus.TotalDelegation
				status.ClaimedReward = networkStatus.ClaimedReward
				status.ClaimableReward = networkStatus.ClaimableReward
				status.CreatedAt = networkStatus.CreatedAt

				// Set the network status
				if networkStatus.Status != "" {
					status.NetworkStatus = networkStatus.Status
					log.Debugf("Node %s has network status: %s", status.Instance, status.NetworkStatus)
				} else {
					status.NetworkStatus = "active" // Normal registered node
				}
			} else {
				// We have a peer ID but no network status - this is a newly created node
				status.NetworkStatus = "unregistered"
				log.Debugf("Node %s has peer ID %s but no network status, marking as unregistered", status.Instance, status.PeerID)
			}
		}

		// Determine if the node is healthy
		status.Healthy = m.isNodeHealthy(status)
		if !status.Healthy {
			unhealthyNodes[status.Instance] = m.getUnhealthyReason(status)
		}

		updates[node.Instance] = status
	}

	// Update all nodes
	for instance, status := range updates {
		// Check if node was previously healthy (needed for health status tracking)
		wasHealthy := true
		if existing, ok := m.nodes[instance]; ok {
			wasHealthy = existing.Healthy
			status.LastRestart = existing.LastRestart
			status.RestartCount = existing.RestartCount
		}

		// Load restart info from persistent history if we don't have it in memory
		if status.LastRestart.IsZero() {
			if restartInfo, ok := m.restartHistory.Nodes[instance]; ok {
				status.LastRestart = restartInfo.LastRestart
				status.RestartCount = restartInfo.RestartCount
				log.Infof("Loaded persistent restart info for %s: last restart %s, count %d",
					instance, status.LastRestart.Format(time.RFC3339), status.RestartCount)
			} else {
				log.Infof("No persistent restart history found for %s", instance)
			}
		} else {
			log.Debugf("Node %s already has restart info in memory: last restart %s, count %d",
				instance, status.LastRestart.Format(time.RFC3339), status.RestartCount)
		}

		m.nodes[instance] = status

		// Log health status changes (but don't send notifications - those only happen on restart attempts)
		if wasHealthy && !status.Healthy {
			reason := unhealthyNodes[instance]
			log.Infof("Node %s became unhealthy: %s", instance, reason)
		} else if !wasHealthy && status.Healthy {
			log.Infof("Node %s became healthy", instance)
		}
	}

	// Remove nodes that are no longer present
	for instance := range m.nodes {
		if _, exists := discoveredInstances[instance]; !exists {
			delete(m.nodes, instance)
		}
	}

	// Update metrics if exporter is set
	if m.metricsExporter != nil {
		m.metricsExporter.UpdateMetrics()
	}

	// Update Vector configuration with current node statuses
	if err := m.updateVectorConfig(ctx); err != nil {
		log.Errorf("Failed to update Vector config: %v", err)
		// Don't fail the entire operation for Vector config update failures
	}

	// Periodically flush restart history to disk
	if err := m.flushRestartHistory(); err != nil {
		log.Warnf("Failed to flush restart history: %v", err)
	}

	return nil
}

// takeActions takes actions on unhealthy nodes
// dryRun when true will log actions but not execute them
func (m *Monitor) takeActions(ctx context.Context, dryRun bool) error {
	now := time.Now()
	log.Infof("takeActions called - checking %d nodes, dryRun=%t", len(m.nodes), dryRun)

	unhealthyCount := 0
	for _, node := range m.nodes {
		if !node.Healthy {
			unhealthyCount++
		}
	}
	log.Infof("Found %d unhealthy nodes out of %d total", unhealthyCount, len(m.nodes))

	for _, node := range m.nodes {
		// Skip healthy nodes
		if node.Healthy {
			log.Debugf("Node %s is healthy, skipping", node.Instance)
			continue
		}

		// Skip nodes that are intentionally stopped
		if node.LocalStatus == "stopped" {
			log.Infof("Node %s is intentionally stopped, skipping restart", node.Instance)
			continue
		}

		log.Infof("Processing unhealthy node %s - LocalStatus: %s, Online: %t, Jailed: %t, NetworkStatus: %s", 
			node.Instance, node.LocalStatus, node.Online, node.Jailed, node.NetworkStatus)

		// Log detailed restart timing information for unhealthy nodes
		if node.LastRestart.IsZero() {
			log.Infof("Node %s is unhealthy and has no restart history - eligible for restart", node.Instance)
		} else {
			timeSinceRestart := now.Sub(node.LastRestart)
			log.Infof("Node %s is unhealthy - last restart: %s (%s ago), action period: %s, eligible: %t", 
				node.Instance, 
				node.LastRestart.Format(time.RFC3339), 
				timeSinceRestart.Round(time.Second),
				m.config.ActionPeriod,
				timeSinceRestart >= m.config.ActionPeriod)
		}

		// Skip nodes that were restarted recently
		if !node.LastRestart.IsZero() && now.Sub(node.LastRestart) < m.config.ActionPeriod {
			log.Infof("Skipping restart for %s: last restart was %s ago, need to wait %s",
				node.Instance,
				now.Sub(node.LastRestart).Round(time.Second),
				m.config.ActionPeriod)
			continue
		}

		reason := m.getUnhealthyReason(node)
		log.Infof("Node %s is eligible for restart. Reason: %s", node.Instance, reason)

		if dryRun {
			log.Infof("Would attempt to restart node %s (restart count: %d). Reason: %s",
				node.Instance, node.RestartCount+1, reason)
			// Still send notifications in dry-run mode if notifications are enabled
			if m.config.Notifications.Enabled {
				for _, notifier := range m.notifiers {
					if err := notifier.NotifyNodeRestartAttempt(node, reason); err != nil {
						log.Errorf("Error sending dry-run restart attempt notification: %v", err)
					}
				}
			}
			continue
		}

		// Actual restart logic for non-dry-run mode
		restartStartTime := time.Now()
		node.RestartStartTime = restartStartTime
		
		log.Infof("Attempting to restart node %s (restart count: %d). Reason: %s",
			node.Instance, node.RestartCount+1, reason)
		
		// Send restart attempt notification
		for _, notifier := range m.notifiers {
			if err := notifier.NotifyNodeRestartAttempt(node, reason); err != nil {
				log.Errorf("Error sending restart attempt notification: %v", err)
			}
		}

		// Grafana region annotation will be created after restart completes (success or failure)

		err := m.discoverer.RestartNode(node.Instance)

		// Update restart information both in memory and persistent storage
		node.LastRestart = now
		node.RestartCount++

		// Update restart history
		m.restartHistory.Nodes[node.Instance] = NodeRestartInfo{
			LastRestart:  node.LastRestart,
			RestartCount: node.RestartCount,
		}

		// Save to persistent storage (batched)
		if err := m.saveRestartHistory(); err != nil {
			log.Warnf("Failed to save restart history: %v", err)
		}

		if err != nil {
			log.Errorf("Failed to restart node %s: %v", node.Instance, err)
			
			// Send restart failure notifications
			for _, notifier := range m.notifiers {
				if err := notifier.NotifyNodeRestartFailure(node, reason, err); err != nil {
					log.Errorf("Error sending restart failure notification: %v", err)
				}
			}
			
			// Send Grafana region annotation for restart failure
			m.sendRestartAnnotation(node, restartStartTime, false, reason, err)
			
			// Continue to process other nodes instead of returning
			continue
		}

		// Notify restart success
		for _, notifier := range m.notifiers {
			if err := notifier.NotifyNodeRestartSuccess(node, reason); err != nil {
				log.Errorf("Error sending restart success notification: %v", err)
			}
		}
		
		// Send Grafana region annotation for restart success
		m.sendRestartAnnotation(node, restartStartTime, true, reason, nil)

		log.Infof("Successfully restarted node %s (restart count: %d)", node.Instance, node.RestartCount)
	}

	return nil
}

// sendRestartAnnotation sends a single region annotation for the restart operation
func (m *Monitor) sendRestartAnnotation(node *NodeStatus, startTime time.Time, success bool, reason string, restartErr error) {
	endTime := time.Now().UnixMilli()
	startTimeMs := startTime.UnixMilli()
	
	var tag, text string
	if success {
		tag = "sqd-restart-success"
		text = fmt.Sprintf("Node restart successful: %s (Reason: %s)", node.Instance, reason)
	} else {
		tag = "sqd-restart-failure"
		text = fmt.Sprintf("Node restart failed: %s (Reason: %s, Error: %v)", node.Instance, reason, restartErr)
	}
	
	annotation := grafana.Annotation{
		Time:    startTimeMs,
		TimeEnd: &endTime,
		Tags: []string{
			tag,
			node.Instance,
			node.Name,
			m.hostname,
			node.PeerID,
			reason,
		},
		Text: text,
	}
	
	log.Debugf("Attempting to send Grafana annotation: enabled=%t, enableAnnotations=%t, url=%s", 
		m.config.Notifications.Enabled, 
		m.config.Notifications.EnableAnnotations, 
		m.config.Notifications.AnnotationURL)
	
	if err := grafana.SendAnnotation(m.config, annotation); err != nil {
		log.Warnf("Failed to send Grafana annotation for restart: %v", err)
	} else {
		log.Infof("Successfully sent Grafana annotation for %s restart", node.Instance)
	}
}

// isNodeHealthy determines if a node is healthy based on its status
func (m *Monitor) isNodeHealthy(node *NodeStatus) bool {
	// Check local status
	if node.LocalStatus == "failed" {
		return false
	}

	// Special handling for nodes with unregistered network status (newly created nodes)
	if node.NetworkStatus == "unregistered" {
		// For unregistered nodes, only check that they're running locally
		// This gives newly created nodes time to register on the network
		log.Debugf("Node %s has unregistered network status, considering healthy if running locally", node.Instance)
		return true
	}

	// If node was created within the last 12 hours, consider it healthy regardless of other statuses
	if !node.CreatedAt.IsZero() && time.Since(node.CreatedAt) <= 12*time.Hour {
		log.Debugf("Node %s was created within the last 12 hours, considering healthy during grace period", node.Instance)
		return true
	}

	// Check network status
	if !node.Online {
		return false
	}

	// Check if jailed
	if node.Jailed {
		return false
	}

	// Check APR
	if node.APR <= 0 {
		return false
	}

	return true
}

// getUnhealthyReason returns a human-readable reason why a node is unhealthy
func (m *Monitor) getUnhealthyReason(node *NodeStatus) string {
	if node.LocalStatus == "failed" {
		return fmt.Sprintf("Node is not running locally (status: %s)", node.LocalStatus)
	}

	if node.NetworkStatus == "unregistered" {
		return "Node is not yet registered on the network"
	}

	if !node.Online {
		return "Node is offline on the network"
	}

	if node.Jailed {
		return fmt.Sprintf("Node is jailed: %s", node.JailReason)
	}

	if node.APR <= 0 {
		return "Node has zero or negative APR"
	}

	return "Unknown reason"
}

// GetNodeStatuses returns a copy of the current node statuses
func (m *Monitor) GetNodeStatuses() map[string]*NodeStatus {
	log.Debug("Starting GetNodeStatuses")

	result := make(map[string]*NodeStatus, len(m.nodes))
	for k, v := range m.nodes {
		// Create a copy of the status to avoid external modification of our internal state
		statusCopy := *v
		result[k] = &statusCopy
	}

	log.Debugf("GetNodeStatuses returning %d nodes", len(result))
	return result
}
