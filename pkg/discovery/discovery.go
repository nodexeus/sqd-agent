package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/config"
	log "github.com/sirupsen/logrus"
)

// NodeInfo contains information about a discovered SQD node
type NodeInfo struct {
	Instance     string // Instance name
	PeerID       string // Peer ID of the node
	Name         string // Name of the node from GraphQL
	LocalName    string // Local name of the node (from the instance list)
	LocalIp      string // Local IP of the node (from the instance list)
	ImageVersion string // Version of the node from the image
	Version      string // Version of the node from GraphQL
	LocalStatus  string // Local status (running, stopped, failed)
}

// Discoverer is responsible for discovering SQD nodes on the server
type Discoverer struct {
	config *config.Config
}

// NewDiscoverer creates a new node discoverer
func NewDiscoverer(cfg *config.Config) *Discoverer {
	return &Discoverer{
		config: cfg,
	}
}

// DiscoverNodes discovers all SQD nodes running on the server
func (d *Discoverer) DiscoverNodes() ([]NodeInfo, error) {
	// Execute the discover nodes command with 30 second timeout
	ctx := context.Background()
	stdout, stderr, err := execCommand(ctx, d.config.Commands.DiscoverNodes, 30*time.Second)
	if err != nil {
		log.Errorf("Failed to discover nodes: %v, stderr: %s", err, stderr)
		return nil, fmt.Errorf("failed to discover nodes: %w, stderr: %s", err, stderr)
	}

	// Parse the output to get instance names
	nodes := parseInstanceList(stdout)

	log.Debugf("Discovered %d nodes: %v", len(nodes), nodeNames(nodes))

	// Get additional information for each instance
	for i, node := range nodes {
		// Get peer ID
		peerID, err := d.getNodePeerID(node.Instance)
		if err != nil {
			// Log but continue with other nodes
			log.Warnf("Failed to get peer ID for instance %s: %v", node.Instance, err)
		} else {
			nodes[i].PeerID = peerID
			log.Debugf("Node %s has peer ID %s", node.Instance, peerID)
		}
	}

	return nodes, nil
}

// Helper function to extract node names for logging
func nodeNames(nodes []NodeInfo) []string {
	names := make([]string, len(nodes))
	for i, node := range nodes {
		names[i] = fmt.Sprintf("%s (%s)", node.Name, node.LocalStatus)
	}
	return names
}

// getNodePeerID gets the peer ID for a specific node instance
func (d *Discoverer) getNodePeerID(instance string) (string, error) {
	ctx := context.Background()
	command := fmt.Sprintf("%s %s", d.config.Commands.GetNodePeerID, instance)
	stdout, stderr, err := execCommand(ctx, command, 10*time.Second)
	if err != nil {
		log.Debugf("Get peer ID command failed for %s: %v, stderr: %s", instance, err, stderr)
		return "", fmt.Errorf("failed to get peer ID: %w, stderr: %s", err, stderr)
	}

	return strings.TrimSpace(stdout), nil
}

// getNodeStatus gets the local status for a specific node instance
func (d *Discoverer) getNodeStatus(instance string) (string, error) {
	ctx := context.Background()
	command := fmt.Sprintf("%s %s", d.config.Commands.GetNodeStatus, instance)
	stdout, stderr, err := execCommand(ctx, command, 10*time.Second)
	if err != nil {
		log.Debugf("Node status command failed for %s: %v, stderr: %s", instance, err, stderr)
		return "failed", nil
	}

	status := strings.TrimSpace(stdout)
	log.Debugf("Node %s status: %s", instance, status)
	return status, nil
}

// RestartNode restarts a specific node instance
func (d *Discoverer) RestartNode(instance string) error {
	log.Infof("Attempting to restart node %s", instance)

	ctx := context.Background()
	command := fmt.Sprintf("%s %s", d.config.Commands.RestartNode, instance)
	_, stderr, err := execCommand(ctx, command, 60*time.Second) // Longer timeout for restart operations
	if err != nil {
		log.Errorf("Failed to restart node %s: %v, stderr: %s", instance, err, stderr)
		return fmt.Errorf("failed to restart node: %w, stderr: %s", err, stderr)
	}

	log.Infof("Successfully restarted node %s", instance)
	return nil
}

// parseInstanceList parses the output of the discover nodes command
func parseInstanceList(output string) []NodeInfo {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var nodes []NodeInfo

	// Skip the header lines (first two lines and last line)
	if len(lines) <= 3 {
		return nodes
	}

	// Process each line (skipping header and footer)
	for i := 2; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Split the line by whitespace, but preserve quoted strings
		fields := splitFields(line)
		if len(fields) < 4 {
			log.Warnf("Unexpected format in node list line: %s", line)
			continue
		}

		// Extract node information
		// Format: ID Name Image State IP Uptime
		nodeID := fields[0]
		nodeName := fields[1]
		nodeState := strings.ToLower(fields[3]) // Convert to lowercase for consistency
		nodeIp := fields[4]
		imageVersion := strings.Split(fields[2], "/")[2]

		// Create NodeInfo
		node := NodeInfo{
			Instance:     nodeID,
			Name:         nodeName,
			LocalName:    nodeName, // Store the local name
			LocalStatus:  nodeState,
			LocalIp:      nodeIp,
			ImageVersion: imageVersion,
		}

		nodes = append(nodes, node)
	}

	return nodes
}

// splitFields splits a line by whitespace, but preserves quoted strings
func splitFields(line string) []string {
	var fields []string
	var currentField strings.Builder
	inQuotes := false

	// Add a space at the end to ensure the last field is processed
	line = line + " "

	for i := 0; i < len(line); i++ {
		char := line[i]

		if char == '"' {
			inQuotes = !inQuotes
			continue
		}

		if char == ' ' && !inQuotes {
			// End of field
			if currentField.Len() > 0 {
				fields = append(fields, currentField.String())
				currentField.Reset()
			}
			continue
		}

		currentField.WriteByte(char)
	}

	return fields
}
