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
	PeerID      string  `json:"peerId"`
	APR         float64 `json:"apr"`
	Online      bool    `json:"online"`
	Jailed      bool    `json:"jailed"`
	JailedReason string  `json:"jailedReason"`
}

// GraphQLClient is a client for the SQD GraphQL API
type GraphQLClient struct {
	config     *config.Config
	httpClient *http.Client
}

// NewGraphQLClient creates a new GraphQL client
func NewGraphQLClient(cfg *config.Config) *GraphQLClient {
	return &GraphQLClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
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
		node(peerId: $peerId) {
			peerId
			apr
			online
			jailed
			jailedReason
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
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing GraphQL request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		return nil, fmt.Errorf("error unmarshaling GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
	}

	// Extract node data
	nodeData, ok := graphQLResp.Data["node"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format: node data not found")
	}

	// Parse the node data
	status := &NodeNetworkStatus{}

	// Extract peer ID
	if peerID, ok := nodeData["peerId"].(string); ok {
		status.PeerID = peerID
	}

	// Extract APR
	if apr, ok := nodeData["apr"].(float64); ok {
		status.APR = apr
	}

	// Extract online status
	if online, ok := nodeData["online"].(bool); ok {
		status.Online = online
	}

	// Extract jailed status
	if jailed, ok := nodeData["jailed"].(bool); ok {
		status.Jailed = jailed
	}

	// Extract jailed reason
	if jailedReason, ok := nodeData["jailedReason"].(string); ok {
		status.JailedReason = jailedReason
	}

	return status, nil
}

// GetAllNodesStatus gets the network status of all nodes
func (c *GraphQLClient) GetAllNodesStatus(ctx context.Context) (map[string]*NodeNetworkStatus, error) {
	// This is a placeholder query - will be replaced with the actual query later
	query := `
	query GetAllNodesStatus {
		nodes {
			peerId
			apr
			online
			jailed
			jailedReason
		}
	}
	`

	// Create the request
	reqBody, err := json.Marshal(GraphQLRequest{
		Query: query,
	})
	if err != nil {
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
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing GraphQL request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		return nil, fmt.Errorf("error unmarshaling GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
	}

	// Extract nodes data
	nodesData, ok := graphQLResp.Data["nodes"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format: nodes data not found")
	}

	// Parse the nodes data
	result := make(map[string]*NodeNetworkStatus)
	for _, nodeInterface := range nodesData {
		nodeData, ok := nodeInterface.(map[string]interface{})
		if !ok {
			continue
		}

		status := &NodeNetworkStatus{}

		// Extract peer ID
		peerID, ok := nodeData["peerId"].(string)
		if !ok {
			continue
		}
		status.PeerID = peerID

		// Extract APR
		if apr, ok := nodeData["apr"].(float64); ok {
			status.APR = apr
		}

		// Extract online status
		if online, ok := nodeData["online"].(bool); ok {
			status.Online = online
		}

		// Extract jailed status
		if jailed, ok := nodeData["jailed"].(bool); ok {
			status.Jailed = jailed
		}

		// Extract jailed reason
		if jailedReason, ok := nodeData["jailedReason"].(string); ok {
			status.JailedReason = jailedReason
		}

		result[peerID] = status
	}

	return result, nil
}
