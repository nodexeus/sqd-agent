package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/config"
)

// NodeNetworkStatus represents the network status of a node from the GraphQL API
type NodeNetworkStatus struct {
	PeerID     string  `json:"peerId"`
	Name       string  `json:"name"`
	APR        float64 `json:"apr"`
	Online     bool    `json:"online"`
	Jailed     bool    `json:"jailed"`
	JailReason string  `json:"jailReason"`
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
	if !ok || len(workers) == 0 {
		c.lastError = fmt.Errorf("no worker found with peer ID %s", peerID)
		c.lastErrorTime = time.Now()
		c.connected = false
		return nil, fmt.Errorf("no worker found with peer ID %s", peerID)
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

	// If we got here, the request was successful
	c.lastError = nil
	c.lastErrorTime = time.Time{}
	c.connected = true
	return status, nil
}

// GetAllNodesStatus gets the network status of all nodes
// func (c *GraphQLClient) GetAllNodesStatus(ctx context.Context) (map[string]*NodeNetworkStatus, error) {
// 	// This is a placeholder query - will be replaced with the actual query later
// 	query := `
// 	query GetAllNodesStatus {
// 		workers {
// 			peerId
// 			name
// 			apr
// 			online
// 			jailed
// 			jailReason
// 		}
// 	}
// 	`

// 	// Create the request
// 	reqBody, err := json.Marshal(GraphQLRequest{
// 		Query: query,
// 	})
// 	if err != nil {
// 		c.lastError = err
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("error marshaling GraphQL request: %w", err)
// 	}

// 	// Create HTTP request
// 	req, err := http.NewRequestWithContext(
// 		ctx,
// 		http.MethodPost,
// 		c.config.GraphQL.Endpoint,
// 		bytes.NewBuffer(reqBody),
// 	)
// 	if err != nil {
// 		c.lastError = err
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("error creating HTTP request: %w", err)
// 	}

// 	// Set headers
// 	req.Header.Set("Content-Type", "application/json")

// 	// Execute the request
// 	resp, err := c.httpClient.Do(req)
// 	if err != nil {
// 		c.lastError = err
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("error executing GraphQL request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	// Read the response body
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		c.lastError = err
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("error reading response body: %w", err)
// 	}

// 	// Parse the response
// 	var graphQLResp GraphQLResponse
// 	if err := json.Unmarshal(body, &graphQLResp); err != nil {
// 		c.lastError = err
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("error unmarshaling GraphQL response: %w", err)
// 	}

// 	// Check for GraphQL errors
// 	if len(graphQLResp.Errors) > 0 {
// 		c.lastError = fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
// 	}

// 	// Extract nodes data
// 	nodesData, ok := graphQLResp.Data["nodes"].([]interface{})
// 	if !ok {
// 		c.lastError = fmt.Errorf("unexpected response format: nodes data not found")
// 		c.lastErrorTime = time.Now()
// 		c.connected = false
// 		return nil, fmt.Errorf("unexpected response format: nodes data not found")
// 	}

// 	// Parse the nodes data
// 	result := make(map[string]*NodeNetworkStatus)
// 	for _, nodeInterface := range nodesData {
// 		nodeData, ok := nodeInterface.(map[string]interface{})
// 		if !ok {
// 			continue
// 		}

// 		status := &NodeNetworkStatus{}

// 		// Extract peer ID
// 		peerID, ok := nodeData["peerId"].(string)
// 		if !ok {
// 			continue
// 		}
// 		status.PeerID = peerID

// 		// Extract name
// 		if name, ok := nodeData["name"].(string); ok {
// 			status.Name = name
// 		}

// 		// Extract APR
// 		if apr, ok := nodeData["apr"].(float64); ok {
// 			status.APR = apr
// 		}

// 		// Extract online status
// 		if online, ok := nodeData["online"].(bool); ok {
// 			status.Online = online
// 		}

// 		// Extract jailed status
// 		if jailed, ok := nodeData["jailed"].(bool); ok {
// 			status.Jailed = jailed
// 		}

// 		// Extract jailed reason
// 		if jailReason, ok := nodeData["jailReason"].(string); ok {
// 			status.JailReason = jailReason
// 		}

// 		result[peerID] = status
// 	}

// 	c.lastError = nil
// 	c.lastErrorTime = time.Time{}
// 	c.connected = true
// 	return result, nil
// }

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
