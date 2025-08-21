package httpclient

import (
	"net/http"
	"time"
)

var (
	// DefaultClient provides a shared HTTP client with optimized connection pooling
	DefaultClient *http.Client
	// LongTimeoutClient provides a client with longer timeout for operations like updates
	LongTimeoutClient *http.Client
)

func init() {
	// Create a transport with optimized connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	// Standard timeout client (30s)
	DefaultClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	// Long timeout client (60s) for operations like updates
	LongTimeoutClient = &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}
}