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
	instances := parseInstanceList(stdout.String())
	
	// Get additional information for each instance
	nodes := make([]NodeInfo, 0, len(instances))
	for _, instance := range instances {
		node := NodeInfo{
			Instance: instance,
		}
		
		// Get peer ID
		peerID, err := d.getNodePeerID(instance)
		if err != nil {
			// Log but continue with other nodes
			fmt.Printf("Warning: failed to get peer ID for instance %s: %v\n", instance, err)
		} else {
			node.PeerID = peerID
		}
		
		// Get local status
		status, err := d.getNodeStatus(instance)
		if err != nil {
			// Log but continue with other nodes
			fmt.Printf("Warning: failed to get status for instance %s: %v\n", instance, err)
		} else {
			node.LocalStatus = status
		}
		
		nodes = append(nodes, node)
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
func parseInstanceList(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var instances []string
	
	for _, line := range lines {
		if line != "" {
			instances = append(instances, strings.TrimSpace(line))
		}
	}
	
	return instances
}
