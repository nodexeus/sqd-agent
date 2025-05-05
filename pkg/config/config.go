package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration for the SQD agent
type Config struct {
	// General settings
	LogLevel      string        `yaml:"logLevel"`
	MonitorPeriod time.Duration `yaml:"monitorPeriod"`
	ActionPeriod  time.Duration `yaml:"actionPeriod"`
	PassiveMode   bool          `yaml:"passiveMode"`
	AutoUpdate    bool          `yaml:"autoUpdate"`

	// Notification settings
	Notifications NotificationConfig `yaml:"notifications"`

	// Prometheus metrics settings
	Prometheus PrometheusConfig `yaml:"prometheus"`

	// GraphQL API settings
	GraphQL GraphQLConfig `yaml:"graphql"`

	// Custom commands
	Commands CommandsConfig `yaml:"commands"`
}

// NotificationConfig contains notification-related settings
type NotificationConfig struct {
	Enabled         bool          `yaml:"enabled"`
	WebhookEnabled  bool          `yaml:"webhookEnabled"`
	WebhookURL      string        `yaml:"webhookUrl"`
	DiscordEnabled  bool          `yaml:"discordEnabled"`
	DiscordWebhooks []DiscordHook `yaml:"discordWebhooks"`
}

// DiscordHook represents a Discord webhook configuration
type DiscordHook struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// PrometheusConfig contains Prometheus metrics-related settings
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// GraphQLConfig contains GraphQL API-related settings
type GraphQLConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// CommandsConfig contains custom commands configuration
type CommandsConfig struct {
	DiscoverNodes string `yaml:"discoverNodes"`
	GetNodePeerID string `yaml:"getNodePeerID"`
	RestartNode   string `yaml:"restartNode"`
	GetNodeStatus string `yaml:"getNodeStatus"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		LogLevel:      "info",
		MonitorPeriod: 1 * time.Minute,
		ActionPeriod:  5 * time.Minute,
		PassiveMode:   false,
		AutoUpdate:    true,
		Notifications: NotificationConfig{
			Enabled:        true,
			WebhookEnabled: false,
			DiscordEnabled: true,
			DiscordWebhooks: []DiscordHook{
				{
					Name: "Alerts",
					URL:  "https://discord.com/api/webhooks/1368593518771044473/7VfHvNFKIvk5srMsxxU-RpzWSJgQLgOmqICMS-8E-w9cU9up7DOexyXwLXoamrkS9HY2",
				},
			},
		},
		Prometheus: PrometheusConfig{
			Enabled: true,
			Port:    9090,
			Path:    "/metrics",
		},
		GraphQL: GraphQLConfig{
			Endpoint: "https://subsquid.squids.live/subsquid-network-mainnet/graphql",
		},
		Commands: CommandsConfig{
			DiscoverNodes: "bv node ls",
			GetNodePeerID: "bv node run address",
			RestartNode:   "bv node restart",
			GetNodeStatus: "bv node status",
		},
	}
}

// LoadConfig loads the configuration from the given file path
func LoadConfig(path string) (*Config, error) {
	// Set default config
	config := DefaultConfig()

	// Read config file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, fmt.Errorf("config file not found at %s, using defaults", path)
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return config, nil
}

// SaveConfig saves the configuration to the given file path
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	err = ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
