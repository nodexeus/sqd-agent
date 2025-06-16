package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/config"
)

// NodeNetworkStatus represents the network status of a node from the GraphQL API
type NodeNetworkStatus struct {
	PeerID            string   `json:"peerId"`
	Name              string   `json:"name"`
	APR               float64  `json:"apr"`
	Online            bool     `json:"online"`
	Jailed            bool     `json:"jailed"`
	JailReason        string   `json:"jailReason"`
	Queries24Hours    int64    `json:"queries24Hours"`
	Uptime24Hours     float64  `json:"uptime24Hours"`
	Version           string   `json:"version"`
	ServedData24Hours int64    `json:"servedData24Hours"`
	StoredData        *big.Int `json:"storedData"`
	TotalDelegation   *big.Int `json:"totalDelegation"`
	ClaimedReward     *big.Int `json:"claimedReward"`
	ClaimableReward   *big.Int `json:"claimableReward"`
	// Status is used for tracking special states like "pending" for newly created nodes
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

// GraphQLClient is a client for the SQD GraphQL API
type GraphQLClient struct {
	config        *config.Config
	httpClient    *http.Client
	lastError     error
	lastErrorTime time.Time
	connected     bool
}

// NewGraphQLClient creates a new GraphQL client
func NewGraphQLClient(cfg *config.Config) *GraphQLClient {
	return &GraphQLClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		connected:     false,
		lastErrorTime: time.Now(),
	}
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data   map[string]interface{} `json:"data"`
	Errors []GraphQLError         `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message string `json:"message"`
}

// GetNodeStatus gets the network status of a node by its peer ID
func (c *GraphQLClient) GetNodeStatus(ctx context.Context, peerID string) (*NodeNetworkStatus, error) {
	// This is a placeholder query - will be replaced with the actual query later
	query := `
	query GetNodeStatus($peerId: String!) {
		workers(where: {peerId_eq: $peerId}) {
			apr
			name
			online
			jailed
			jailReason
			peerId
			queries24Hours
			uptime24Hours
			version
			servedData24Hours
			storedData
			totalDelegation
			claimedReward
			claimableReward
			createdAt
		}
	}
	`

	variables := map[string]interface{}{
		"peerId": peerID,
	}

	// Create the request
	reqBody, err := json.Marshal(GraphQLRequest{
		Query:     query,
		Variables: variables,
	})
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("error marshaling GraphQL request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.config.GraphQL.Endpoint,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("error executing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		c.lastError = fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("error parsing GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		c.lastError = fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
	}

	// Extract node status from response
	workers, ok := graphQLResp.Data["workers"].([]interface{})
	if !ok {
		c.lastError = fmt.Errorf("invalid response format for workers")
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("invalid response format for workers")
	}

	// Handle empty workers list as a special case for new nodes
	if len(workers) == 0 {
		// This is a valid case for a new node that's not yet registered on the network
		// Return a status with just the peer ID and mark it as "unregistered"
		c.connected = true // API connection is fine, just no data for this node yet
		return &NodeNetworkStatus{
			PeerID: peerID,
			Status: "unregistered", // Special status for nodes not yet registered on network
		}, nil
	}

	worker := workers[0].(map[string]interface{})
	status := &NodeNetworkStatus{}

	// Safely extract fields with nil checks
	if peerID, ok := worker["peerId"].(string); ok {
		status.PeerID = peerID
	}
	if name, ok := worker["name"].(string); ok {
		status.Name = name
	}
	if apr, ok := worker["apr"].(float64); ok {
		status.APR = apr
	}
	if online, ok := worker["online"].(bool); ok {
		status.Online = online
	}
	if jailed, ok := worker["jailed"].(bool); ok {
		status.Jailed = jailed
	}
	if jailReason, ok := worker["jailReason"].(string); ok {
		status.JailReason = jailReason
	}
	if queries24Hours, ok := worker["queries24Hours"].(string); ok {
		value, err := strconv.ParseInt(queries24Hours, 10, 64)
		if err == nil {
			status.Queries24Hours = value
		}
	} else if val, ok := worker["queries24Hours"].(float64); ok {
		status.Queries24Hours = int64(val)
	}

	if uptime24Hours, ok := worker["uptime24Hours"].(float64); ok {
		status.Uptime24Hours = uptime24Hours
	} else if str, ok := worker["uptime24Hours"].(string); ok {
		value, err := strconv.ParseFloat(str, 64)
		if err == nil {
			status.Uptime24Hours = value
		}
	}

	if version, ok := worker["version"].(string); ok {
		status.Version = version
	}

	if servedData24Hours, ok := worker["servedData24Hours"].(string); ok {
		value, err := strconv.ParseInt(servedData24Hours, 10, 64)
		if err == nil {
			status.ServedData24Hours = value
		}
	}

	if storedData, ok := worker["storedData"].(string); ok {
		value, err := strconv.ParseInt(storedData, 10, 64)
		if err == nil {
			status.StoredData = big.NewInt(value)
		}
	}

	if totalDelegation, ok := worker["totalDelegation"].(string); ok {
		value, err := strconv.ParseInt(totalDelegation, 10, 64)
		if err == nil {
			status.TotalDelegation = big.NewInt(value)
		}
	}

	if claimedReward, ok := worker["claimedReward"].(string); ok {
		value, err := strconv.ParseInt(claimedReward, 10, 64)
		if err == nil {
			status.ClaimedReward = big.NewInt(value)
		}
	}

	if claimableReward, ok := worker["claimableReward"].(string); ok {
		value, err := strconv.ParseInt(claimableReward, 10, 64)
		if err == nil {
			status.ClaimableReward = big.NewInt(value)
		}
	}

	// If we got here, the request was successful
	c.lastError = nil
	c.lastErrorTime = time.Time{}
	c.connected = true
	return status, nil
}

// TestConnection tests the connection to the GraphQL endpoint
// Returns true if the connection is successful
func (c *GraphQLClient) TestConnection(ctx context.Context) bool {
	// A simple introspection query to test the connection
	query := `{ __schema { queryType { name } } }`

	// Create the request
	reqBody, err := json.Marshal(GraphQLRequest{
		Query: query,
	})
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.config.GraphQL.Endpoint,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		c.lastError = fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		c.lastError = fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// If we got here, the connection is working
	c.lastError = nil
	c.lastErrorTime = time.Time{}
	c.connected = true
	return true
}

// GetConnectionStatus returns the current connection status
func (c *GraphQLClient) GetConnectionStatus() (bool, error, time.Time) {
	return c.connected, c.lastError, c.lastErrorTime
}

// IsConnected returns whether the client is currently connected
func (c *GraphQLClient) IsConnected() bool {
	return c.connected
}

// GetLastError returns the last error encountered
func (c *GraphQLClient) GetLastError() error {
	return c.lastError
}

// GetLastErrorTime returns the time of the last error
func (c *GraphQLClient) GetLastErrorTime() time.Time {
	return c.lastErrorTime
}
