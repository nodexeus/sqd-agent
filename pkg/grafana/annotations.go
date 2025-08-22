package grafana

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/httpclient"
	log "github.com/sirupsen/logrus"
)

// Annotation represents a Grafana annotation payload
type Annotation struct {
	Time    int64    `json:"time"`
	TimeEnd *int64   `json:"timeEnd,omitempty"`
	Tags    []string `json:"tags"`
	Text    string   `json:"text"`
}

// SendAnnotation sends an annotation to Grafana
func SendAnnotation(config *config.Config, annotation Annotation) error {
	if !config.Notifications.Enabled || !config.Notifications.EnableAnnotations {
		log.Debugf("Grafana annotations disabled: notifications.enabled=%t, enableAnnotations=%t", 
			config.Notifications.Enabled, config.Notifications.EnableAnnotations)
		return nil
	}

	if config.Notifications.AnnotationURL == "" {
		return fmt.Errorf("annotation URL not configured")
	}
	
	log.Debugf("Sending Grafana annotation to %s: %+v", config.Notifications.AnnotationURL, annotation)

	// Prepare the request body
	body, err := json.Marshal(annotation)
	if err != nil {
		return fmt.Errorf("failed to marshal annotation: %w", err)
	}

	// Create the request
	url := config.Notifications.AnnotationURL + "/api/annotations"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create annotation request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := httpclient.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send annotation: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode >= 400 {
		return fmt.Errorf("Grafana annotation API returned error status: %d", resp.StatusCode)
	}

	return nil
}