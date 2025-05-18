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
	LocalStatus       string
	NetworkStatus     string // For special statuses like "pending" for newly created nodes
	APR               float64
	Online            bool
	Jailed            bool
	JailReason        string
	Queries24Hours    int64
	Uptime24Hours     int64
	Version           string
	ServedData24Hours int64
	StoredData        int64
	TotalDelegation   int64
	ClaimedReward     int64
	ClaimableReward   int64
	LastChecked       time.Time
	LastRestart       time.Time
	RestartCount      int // Count restarts for better tracking
	Healthy           bool
}

// Monitor is responsible for monitoring SQD nodes
type Monitor struct {
	config          *config.Config
	discoverer      *discovery.Discoverer
	apiClient       *api.GraphQLClient
	nodes           map[string]*NodeStatus // Map of instance name to node status
	notifiers       []Notifier
	metricsExporter MetricsExporter
	restartHistory  *RestartHistory
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

// saveRestartHistory persists the restart history to disk
func saveRestartHistory(history *RestartHistory) error {
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
	NotifyNodeUnhealthy(node *NodeStatus, reason string) error
	NotifyNodeRestartAttempt(node *NodeStatus, unhealthyReason string) error
	NotifyNodeRestartSuccess(node *NodeStatus, unhealthyReason string) error
	NotifyNodeRestartFailure(node *NodeStatus, unhealthyReason string, err error) error
}

// MetricsExporter is an interface for metrics exporters
type MetricsExporter interface {
	UpdateMetrics()
}

// NewMonitor creates a new node monitor
func NewMonitor(config *config.Config, discoverer *discovery.Discoverer, apiClient *api.GraphQLClient) *Monitor {
	// Load restart history from persistent storage
	history, err := loadRestartHistory()
	if err != nil {
		log.Warnf("Failed to load restart history: %v", err)
		history = &RestartHistory{Nodes: make(map[string]NodeRestartInfo)}
	}

	return &Monitor{
		config:          config,
		discoverer:      discoverer,
		apiClient:       apiClient,
		nodes:           make(map[string]*NodeStatus),
		notifiers:       make([]Notifier, 0),
		metricsExporter: nil,
		restartHistory:  history,
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
	monitorTicker := time.NewTicker(m.config.MonitorPeriod)
	actionTicker := time.NewTicker(m.config.MonitorPeriod)

	go func() {
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
				if err := m.takeActions(ctx, m.config.PassiveMode); err != nil {
					log.Errorf("Error taking actions on nodes: %v", err)
				}
			}
		}
	}()

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
			if status.Name == "" {
				log.Debugf("Node %s has no name, likely unregistered", node.Instance)
				continue
			}
			if err != nil {
				log.Errorf("Failed to get network status for node %s: %v", node.Instance, err)
				// If we get an error, mark the connection as down and break the loop
				if !m.apiClient.IsConnected() {
					log.Warn("GraphQL API connection lost, will retry on next check")
					break
				}
				continue
			}

			log.Debugf("Successfully retrieved network status for node %s: online=%v, jailed=%v, jailReason=%s, name=%s, apr=%f, peerID=%s, version=%s, claimedReward=%d, claimableReward=%d, servedData24Hours=%d, storedData=%d, totalDelegation=%d, uptime24Hours=%d, queries24Hours=%d",
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
			Instance:    node.Instance,
			PeerID:      node.PeerID,
			Name:        node.Name,
			Version:     node.Version,
			LastChecked: time.Now(),
		}

		// Update local status
		status.LocalStatus = node.LocalStatus
		status.PeerID = node.PeerID

		// Update network status if we have a peer ID
		if status.PeerID != "" {
			if networkStatus, ok := networkStatuses[status.PeerID]; ok {
				// Copy all network status fields
				status.APR = networkStatus.APR
				status.Online = networkStatus.Online
				status.Jailed = networkStatus.Jailed
				status.JailReason = networkStatus.JailReason
				status.Name = networkStatus.Name
				status.Queries24Hours = networkStatus.Queries24Hours
				status.Uptime24Hours = networkStatus.Uptime24Hours
				status.Version = networkStatus.Version
				status.ServedData24Hours = networkStatus.ServedData24Hours
				status.StoredData = networkStatus.StoredData
				status.TotalDelegation = networkStatus.TotalDelegation
				status.ClaimedReward = networkStatus.ClaimedReward
				status.ClaimableReward = networkStatus.ClaimableReward

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
		// Check if node was previously healthy
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
				log.Debugf("Loaded persistent restart info for %s: last restart %s, count %d",
					instance, status.LastRestart.Format(time.RFC3339), status.RestartCount)
			}
		}

		m.nodes[instance] = status

		// Notify if node became unhealthy
		if wasHealthy && !status.Healthy {
			reason := unhealthyNodes[instance]
			for _, notifier := range m.notifiers {
				if err := notifier.NotifyNodeUnhealthy(status, reason); err != nil {
					log.Errorf("Error sending unhealthy notification: %v", err)
				}
			}
		}
	}

	// Remove nodes that are no longer present
	for instance := range m.nodes {
		if _, exists := discoveredInstances[instance]; !exists {
			delete(m.nodes, instance)
		}
	}

	// Update metrics if exporter is configured
	if m.metricsExporter != nil {
		log.Debug("Updating Prometheus metrics after node status changes...")
		m.metricsExporter.UpdateMetrics()
	}

	log.Debug("Completed discoverAndCheck")
	return nil
}

// takeActions takes actions on unhealthy nodes
// dryRun when true will log actions but not execute them
func (m *Monitor) takeActions(ctx context.Context, dryRun bool) error {
	now := time.Now()

	for _, node := range m.nodes {
		// Skip healthy nodes
		if node.Healthy {
			continue
		}

		// Skip nodes that were restarted recently
		if !node.LastRestart.IsZero() && now.Sub(node.LastRestart) < m.config.ActionPeriod {
			log.Debugf("Skipping restart for %s: last restart was %s ago, need to wait %s",
				node.Instance,
				now.Sub(node.LastRestart).Round(time.Second),
				m.config.ActionPeriod)
			continue
		}

		reason := m.getUnhealthyReason(node)
		logMsg := fmt.Sprintf("Would restart node %s (restart count: %d). Reason: %s", node.Instance, node.RestartCount+1, reason)

		if dryRun {
			log.Info(logMsg)
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
		log.Info(logMsg)
		for _, notifier := range m.notifiers {
			if err := notifier.NotifyNodeRestartAttempt(node, reason); err != nil {
				log.Errorf("Error sending restart attempt notification: %v", err)
			}
		}

		err := m.discoverer.RestartNode(node.Instance)

		// Update restart information both in memory and persistent storage
		node.LastRestart = now
		node.RestartCount++

		// Update restart history
		m.restartHistory.Nodes[node.Instance] = NodeRestartInfo{
			LastRestart:  node.LastRestart,
			RestartCount: node.RestartCount,
		}

		// Save to persistent storage
		if err := saveRestartHistory(m.restartHistory); err != nil {
			log.Warnf("Failed to save restart history: %v", err)
		}

		if err != nil {
			for _, notifier := range m.notifiers {
				if err := notifier.NotifyNodeRestartFailure(node, reason, err); err != nil {
					log.Errorf("Error sending restart failure notification: %v", err)
				}
			}
			return fmt.Errorf("failed to restart node %s: %w", node.Instance, err)
		}

		// Notify restart success
		for _, notifier := range m.notifiers {
			if err := notifier.NotifyNodeRestartSuccess(node, reason); err != nil {
				log.Errorf("Error sending restart success notification: %v", err)
			}
		}

		log.Infof("Successfully restarted node %s (restart count: %d)", node.Instance, node.RestartCount)
	}

	return nil
}

// isNodeHealthy determines if a node is healthy based on its status
func (m *Monitor) isNodeHealthy(node *NodeStatus) bool {
	// Check local status
	if node.LocalStatus != "running" && node.LocalStatus != "busy" {
		return false
	}

	// Special handling for nodes with unregistered network status (newly created nodes)
	if node.NetworkStatus == "unregistered" {
		// For unregistered nodes, only check that they're running locally
		// This gives newly created nodes time to register on the network
		log.Debugf("Node %s has unregistered network status, considering healthy if running locally", node.Instance)
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
	if node.LocalStatus != "running" && node.LocalStatus != "busy" {
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
