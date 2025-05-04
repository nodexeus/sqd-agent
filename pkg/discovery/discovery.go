package discovery

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nodexeus/sqd-agent/pkg/config"
)

// NodeInfo contains information about a discovered SQD node
type NodeInfo struct {
	Instance    string // Instance name
	PeerID      string // Peer ID of the node
	Name        string // Name of the node from GraphQL
	LocalStatus string // Local status (running, stopped, failed)
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
	// Execute the discover nodes command
	cmd := exec.Command("bash", "-c", d.config.Commands.DiscoverNodes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to discover nodes: %w, stderr: %s", err, stderr.String())
	}
	
	// Parse the output to get instance names
	nodes := parseInstanceList(stdout.String())
	
	// Get additional information for each instance
	for i, node := range nodes {
		// Get peer ID
		peerID, err := d.getNodePeerID(node.Instance)
		if err != nil {
			// Log but continue with other nodes
			fmt.Printf("Warning: failed to get peer ID for instance %s: %v\n", node.Instance, err)
		} else {
			nodes[i].PeerID = peerID
		}
	}
	
	return nodes, nil
}

// getNodePeerID gets the peer ID for a specific node instance
func (d *Discoverer) getNodePeerID(instance string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s %s", d.config.Commands.GetNodePeerID, instance))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get peer ID: %w, stderr: %s", err, stderr.String())
	}
	
	return strings.TrimSpace(stdout.String()), nil
}

// getNodeStatus gets the local status for a specific node instance
func (d *Discoverer) getNodeStatus(instance string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s %s", d.config.Commands.GetNodeStatus, instance))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return "failed", fmt.Errorf("failed to get node status: %w, stderr: %s", err, stderr.String())
	}
	
	output := strings.TrimSpace(stdout.String())
	
	// Parse the status output - this may need to be adjusted based on actual output format
	if strings.Contains(output, "running") {
		return "running", nil
	} else if strings.Contains(output, "stopped") {
		return "stopped", nil
	} else {
		return "unknown", nil
	}
}

// RestartNode attempts to restart a specific node instance
func (d *Discoverer) RestartNode(instance string) error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s %s", d.config.Commands.RestartNode, instance))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart node: %w, stderr: %s", err, stderr.String())
	}
	
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
			fmt.Printf("Warning: unexpected format in node list line: %s\n", line)
			continue
		}
		
		// Extract node information
		// Format: ID Name Image State IP Uptime
		nodeID := fields[0]
		nodeName := fields[1]
		nodeState := strings.ToLower(fields[3]) // Convert to lowercase for consistency
		
		// Create NodeInfo
		node := NodeInfo{
			Instance:    nodeID,
			Name:        nodeName,
			LocalStatus: nodeState,
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
