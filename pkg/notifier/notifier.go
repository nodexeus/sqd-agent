package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/httpclient"
	"github.com/nodexeus/sqd-agent/pkg/monitor"
)

// WebhookNotifier sends notifications to a webhook URL
type WebhookNotifier struct {
	config     *config.Config
	httpClient *http.Client
	hostname   string
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(cfg *config.Config, hostname string) *WebhookNotifier {
	return &WebhookNotifier{
		config:     cfg,
		httpClient: httpclient.DefaultClient,
		hostname:   hostname,
	}
}

// WebhookPayload represents the payload sent to the webhook
type WebhookPayload struct {
	Type            string      `json:"type"`
	Timestamp       time.Time   `json:"timestamp"`
	Node            interface{} `json:"node"`
	Message         string      `json:"message"`
	Error           string      `json:"error,omitempty"`
	Server          string      `json:"server"`
	UnhealthyReason string      `json:"unhealthyReason,omitempty"`
}

// NotifyNodeRestartAttempt notifies that a restart attempt is being made
func (n *WebhookNotifier) NotifyNodeRestartAttempt(node *monitor.NodeStatus, unhealthyReason string) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.WebhookEnabled {
		return nil
	}

	payload := WebhookPayload{
		Type:            "node_restart_attempt",
		Timestamp:       time.Now(),
		Node:            node,
		Message:         fmt.Sprintf("Attempting to restart node %s - Local Status: %s, Online: %t, Jailed: %t, APR: %.2f%%, Reason: %s", 
			node.Instance, node.LocalStatus, node.Online, node.Jailed, node.APR*100, unhealthyReason),
		Server:          n.hostname,
		UnhealthyReason: unhealthyReason,
	}

	return n.sendWebhook(payload)
}

// NotifyNodeRestartSuccess notifies that a restart was successful
func (n *WebhookNotifier) NotifyNodeRestartSuccess(node *monitor.NodeStatus, unhealthyReason string) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.WebhookEnabled {
		return nil
	}

	payload := WebhookPayload{
		Type:            "node_restart_success",
		Timestamp:       time.Now(),
		Node:            node,
		Message:         fmt.Sprintf("Successfully restarted node %s", node.Instance),
		Server:          n.hostname,
		UnhealthyReason: unhealthyReason,
	}

	return n.sendWebhook(payload)
}

// NotifyNodeRestartFailure notifies that a restart failed
func (n *WebhookNotifier) NotifyNodeRestartFailure(node *monitor.NodeStatus, unhealthyReason string, err error) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.WebhookEnabled {
		return nil
	}

	payload := WebhookPayload{
		Type:            "node_restart_failure",
		Timestamp:       time.Now(),
		Node:            node,
		Message:         fmt.Sprintf("Failed to restart node %s", node.Instance),
		Error:           err.Error(),
		Server:          n.hostname,
		UnhealthyReason: unhealthyReason,
	}

	return n.sendWebhook(payload)
}

// sendWebhook sends a payload to the webhook URL
func (n *WebhookNotifier) sendWebhook(payload WebhookPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling webhook payload: %w", err)
	}

	resp, err := n.httpClient.Post(
		n.config.Notifications.WebhookURL,
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return fmt.Errorf("error sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

// DiscordNotifier sends notifications to Discord webhooks
type DiscordNotifier struct {
	config     *config.Config
	httpClient *http.Client
	hostname   string
}

// NewDiscordNotifier creates a new Discord notifier
func NewDiscordNotifier(cfg *config.Config, hostname string) *DiscordNotifier {
	return &DiscordNotifier{
		config:     cfg,
		httpClient: httpclient.DefaultClient,
		hostname:   hostname,
	}
}

// DiscordWebhookPayload represents the payload sent to Discord webhooks
type DiscordWebhookPayload struct {
	Username  string          `json:"username,omitempty"`
	Content   string          `json:"content,omitempty"`
	Embeds    []DiscordEmbed  `json:"embeds,omitempty"`
}

// DiscordEmbed represents a Discord embed
type DiscordEmbed struct {
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color,omitempty"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

// DiscordField represents a field in a Discord embed
type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}


// NotifyNodeRestartAttempt notifies that a restart attempt is being made
func (n *DiscordNotifier) NotifyNodeRestartAttempt(node *monitor.NodeStatus, unhealthyReason string) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.DiscordEnabled {
		return nil
	}

	embed := DiscordEmbed{
		Title:       "Node Restart Attempt",
		Description: fmt.Sprintf("Attempting to restart node %s", node.Instance),
		Color:       16776960, // Yellow
		Fields: []DiscordField{
			{Name: "Instance", Value: node.Instance, Inline: true},
			{Name: "Peer ID", Value: node.PeerID, Inline: true},
			{Name: "SQD Name", Value: node.Name, Inline: false},
			{Name: "Local Status", Value: node.LocalStatus, Inline: true},
			{Name: "Online", Value: fmt.Sprintf("%t", node.Online), Inline: true},
			{Name: "Jailed", Value: fmt.Sprintf("%t", node.Jailed), Inline: true},
			{Name: "APR", Value: fmt.Sprintf("%.2f%%", node.APR*100), Inline: true},
			{Name: "Server", Value: n.hostname, Inline: true},
			{Name: "Reason", Value: unhealthyReason, Inline: false},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payload := DiscordWebhookPayload{
		Username: "SQD Node Monitor",
		Embeds:   []DiscordEmbed{embed},
	}

	return n.sendDiscordWebhooks(payload)
}

// NotifyNodeRestartSuccess notifies that a restart was successful
func (n *DiscordNotifier) NotifyNodeRestartSuccess(node *monitor.NodeStatus, unhealthyReason string) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.DiscordEnabled {
		return nil
	}

	embed := DiscordEmbed{
		Title:       "Node Restart Success",
		Description: fmt.Sprintf("Successfully restarted node %s", node.Instance),
		Color:       65280, // Green
		Fields: []DiscordField{
			{Name: "Instance", Value: node.Instance, Inline: true},
			{Name: "Peer ID", Value: node.PeerID, Inline: true},
			{Name: "SQD Name", Value: node.Name, Inline: false},
			{Name: "Server", Value: n.hostname, Inline: true},
			{Name: "Previous Issue", Value: unhealthyReason, Inline: false},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payload := DiscordWebhookPayload{
		Username: "SQD Node Monitor",
		Embeds:   []DiscordEmbed{embed},
	}

	return n.sendDiscordWebhooks(payload)
}

// NotifyNodeRestartFailure notifies that a restart failed
func (n *DiscordNotifier) NotifyNodeRestartFailure(node *monitor.NodeStatus, unhealthyReason string, err error) error {
	if !n.config.Notifications.Enabled || !n.config.Notifications.DiscordEnabled {
		return nil
	}

	embed := DiscordEmbed{
		Title:       "Node Restart Failure",
		Description: fmt.Sprintf("Failed to restart node %s", node.Instance),
		Color:       16711680, // Red
		Fields: []DiscordField{
			{Name: "Instance", Value: node.Instance, Inline: true},
			{Name: "Peer ID", Value: node.PeerID, Inline: true},
			{Name: "SQD Name", Value: node.Name, Inline: false},
			{Name: "Server", Value: n.hostname, Inline: true},
			{Name: "Issue", Value: unhealthyReason, Inline: false},
			{Name: "Error", Value: err.Error(), Inline: false},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payload := DiscordWebhookPayload{
		Username: "SQD Node Monitor",
		Embeds:   []DiscordEmbed{embed},
	}

	return n.sendDiscordWebhooks(payload)
}

// sendDiscordWebhooks sends a payload to all configured Discord webhooks
func (n *DiscordNotifier) sendDiscordWebhooks(payload DiscordWebhookPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling Discord payload: %w", err)
	}

	var lastErr error
	for _, hook := range n.config.Notifications.DiscordWebhooks {
		resp, err := n.httpClient.Post(
			hook.URL,
			"application/json",
			bytes.NewBuffer(data),
		)
		if err != nil {
			lastErr = fmt.Errorf("error sending to Discord webhook %s: %w", hook.Name, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("Discord webhook %s returned error status: %d", hook.Name, resp.StatusCode)
		}
	}

	return lastErr
}

