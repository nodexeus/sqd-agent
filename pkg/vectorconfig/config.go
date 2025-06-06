package vectorconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	configDir  = "/etc/vector/sources"
	configFile = "sqd_nodes.yaml"
)

// VectorConfig represents the structure of the Vector configuration
type VectorConfig struct {
	Type      string   `yaml:"type"`
	Endpoints []string `yaml:"endpoints"`
}

// NodeInfo represents the minimal node information needed for Vector config
type NodeInfo struct {
	Ip string
}

// GenerateConfig generates the Vector configuration from discovered nodes
func GenerateConfig(nodes []NodeInfo) error {
	// Create endpoints list
	endpoints := make([]string, 0, len(nodes)*2) // 2 endpoints per node (metrics and caddy)

	for _, node := range nodes {
		if node.Ip == "" {
			continue // Skip nodes without names
		}
		// Add both metrics and caddy endpoints
		endpoints = append(endpoints,
			fmt.Sprintf("http://%s/metrics", node.Ip),
			fmt.Sprintf("http://%s/caddy", node.Ip),
		)
	}

	// Create config
	config := VectorConfig{
		Type:      "prometheus_scrape",
		Endpoints: endpoints,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal vector config: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file
	filePath := filepath.Join(configDir, configFile)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write vector config: %w", err)
	}

	return nil
}
