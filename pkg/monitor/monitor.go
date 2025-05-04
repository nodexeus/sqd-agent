package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/api"
	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/discovery"
	log "github.com/sirupsen/logrus"
)

// NodeStatus represents the combined local and network status of a node
type NodeStatus struct {
	Instance    string
	PeerID      string
	Name        string
	LocalStatus string
	APR         float64
	Online      bool
	Jailed      bool
	JailReason  string
	LastChecked time.Time
	LastRestart time.Time
	Healthy     bool
}

// Monitor is responsible for monitoring SQD nodes
type Monitor struct {
	config          *config.Config
	discoverer      *discovery.Discoverer
	apiClient       *api.GraphQLClient
	nodes           map[string]*NodeStatus // Map of instance name to node status
	nodesMu         sync.RWMutex           // Mutex for thread-safe access to nodes map
	notifiers       []Notifier
	metricsExporter MetricsExporter
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
func NewMonitor(cfg *config.Config, discoverer *discovery.Discoverer, apiClient *api.GraphQLClient) *Monitor {
	return &Monitor{
		config:     cfg,
		discoverer: discoverer,
		apiClient:  apiClient,
		nodes:      make(map[string]*NodeStatus),
		notifiers:  make([]Notifier, 0),
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
	actionTicker := time.NewTicker(m.config.ActionPeriod)

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
				if !m.config.PassiveMode {
					if err := m.takeActions(ctx); err != nil {
						log.Errorf("Error taking actions on nodes: %v", err)
					}
				}
			}
		}
	}()

	return nil
}

// discoverAndCheck discovers nodes and checks their status
func (m *Monitor) discoverAndCheck(ctx context.Context) error {
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

			log.Debugf("Successfully retrieved network status for node %s: online=%v, jailed=%v, jailReason=%s, name=%s, apr=%f, peerID=%s",
				node.Instance, status.Online, status.Jailed, status.JailReason, status.Name, status.APR, status.PeerID)

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

	// Update node statuses
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()

	// Create a map to track which nodes we've seen in this discovery
	discoveredInstances := make(map[string]bool)

	for _, node := range nodes {
		discoveredInstances[node.Instance] = true

		// Get or create node status
		status, exists := m.nodes[node.Instance]
		if !exists {
			status = &NodeStatus{
				Instance:    node.Instance,
				PeerID:      node.PeerID,
				Name:        node.Name,
				LastChecked: time.Now(),
			}
			m.nodes[node.Instance] = status
		}

		// Update local status
		status.LocalStatus = node.LocalStatus
		status.PeerID = node.PeerID // Update in case it changed
		status.LastChecked = time.Now()

		// Update network status if we have a peer ID
		if status.PeerID != "" {
			if networkStatus, ok := networkStatuses[status.PeerID]; ok {
				status.APR = networkStatus.APR
				status.Online = networkStatus.Online
				status.Jailed = networkStatus.Jailed
				status.JailReason = networkStatus.JailReason
				status.Name = networkStatus.Name // Update name from network status
			}
		}

		// Determine if the node is healthy
		wasHealthy := status.Healthy
		status.Healthy = m.isNodeHealthy(status)

		// Notify if node became unhealthy
		if wasHealthy && !status.Healthy {
			reason := m.getUnhealthyReason(status)
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

	return nil
}

// takeActions takes actions on unhealthy nodes
func (m *Monitor) takeActions(ctx context.Context) error {
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()

	now := time.Now()

	for _, node := range m.nodes {
		// Skip healthy nodes
		if node.Healthy {
			continue
		}

		// Skip nodes that were restarted recently
		if !node.LastRestart.IsZero() && now.Sub(node.LastRestart) < m.config.ActionPeriod {
			continue
		}

		// Attempt to restart the node
		reason := m.getUnhealthyReason(node)
		for _, notifier := range m.notifiers {
			if err := notifier.NotifyNodeRestartAttempt(node, reason); err != nil {
				log.Errorf("Error sending restart attempt notification: %v", err)
			}
		}

		err := m.discoverer.RestartNode(node.Instance)
		node.LastRestart = now

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
	}

	return nil
}

// isNodeHealthy determines if a node is healthy based on its status
func (m *Monitor) isNodeHealthy(node *NodeStatus) bool {
	// Check local status
	if node.LocalStatus != "running" {
		return false
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
	if node.LocalStatus != "running" {
		return fmt.Sprintf("Node is not running locally (status: %s)", node.LocalStatus)
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
	log.Debug("Attempting to acquire read lock for GetNodeStatuses")

	// Try to acquire the read lock with a timeout
	lockAcquired := make(chan bool, 1)
	go func() {
		m.nodesMu.RLock()
		lockAcquired <- true
	}()

	select {
	case <-lockAcquired:
		defer m.nodesMu.RUnlock()
		log.Debug("Successfully acquired read lock for GetNodeStatuses")

		result := make(map[string]*NodeStatus, len(m.nodes))
		for k, v := range m.nodes {
			// Create a copy of the status to avoid external modification of our internal state
			statusCopy := *v
			result[k] = &statusCopy
		}

		log.Debugf("GetNodeStatuses returning %d nodes", len(result))
		return result
	case <-time.After(5 * time.Second):
		log.Error("Timeout while trying to acquire read lock for GetNodeStatuses")
		return nil
	}
}
