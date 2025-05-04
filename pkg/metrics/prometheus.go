package metrics

import (
	"fmt"
	"net/http"

	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/monitor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// NodeStatusProvider is a function type for getting node statuses
type NodeStatusProvider func() map[string]*monitor.NodeStatus

// PrometheusExporter exports metrics to Prometheus
type PrometheusExporter struct {
	config          *config.Config
	getNodeStatuses NodeStatusProvider
	registry        *prometheus.Registry
	nodeAPR         *prometheus.GaugeVec
	nodeJailed      *prometheus.GaugeVec
	nodeOnline      *prometheus.GaugeVec
	nodeLocalStatus *prometheus.GaugeVec
	nodeHealthy     *prometheus.GaugeVec
	lastRestart     *prometheus.GaugeVec
	server          *http.Server
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(cfg *config.Config, getNodeStatuses NodeStatusProvider) *PrometheusExporter {
	registry := prometheus.NewRegistry()

	exporter := &PrometheusExporter{
		config:          cfg,
		getNodeStatuses: getNodeStatuses,
		registry:        registry,
		nodeAPR: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_apr",
				Help: "Annual Percentage Rate (APR) of the SQD node",
			},
			[]string{"instance", "peer_id", "name"},
		),
		nodeJailed: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_jailed",
				Help: "Whether the SQD node is jailed (1) or not (0)",
			},
			[]string{"instance", "peer_id", "name", "reason"},
		),
		nodeOnline: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_online",
				Help: "Whether the SQD node is online (1) or not (0)",
			},
			[]string{"instance", "peer_id", "name"},
		),
		nodeLocalStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_local_status",
				Help: "Local status of the SQD node (0=failed, 1=stopped, 2=running)",
			},
			[]string{"instance", "peer_id", "name", "status"},
		),
		nodeHealthy: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_healthy",
				Help: "Whether the SQD node is healthy (1) or not (0)",
			},
			[]string{"instance", "peer_id", "name"},
		),
		lastRestart: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_last_restart_timestamp",
				Help: "Timestamp of the last restart attempt for the SQD node",
			},
			[]string{"instance", "peer_id", "name"},
		),
	}

	// Register metrics
	registry.MustRegister(exporter.nodeAPR)
	registry.MustRegister(exporter.nodeJailed)
	registry.MustRegister(exporter.nodeOnline)
	registry.MustRegister(exporter.nodeLocalStatus)
	registry.MustRegister(exporter.nodeHealthy)
	registry.MustRegister(exporter.lastRestart)

	return exporter
}

// Start starts the Prometheus exporter HTTP server
func (e *PrometheusExporter) Start() error {
	if !e.config.Prometheus.Enabled {
		return nil
	}

	// Create HTTP server
	mux := http.NewServeMux()

	// Create handler with the registry
	handler := promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	mux.Handle(e.config.Prometheus.Path, handler)

	e.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", e.config.Prometheus.Port),
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		log.Infof("Starting Prometheus metrics server on port %d at path %s", e.config.Prometheus.Port, e.config.Prometheus.Path)
		if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Error starting Prometheus HTTP server: %v", err)
		}
	}()

	return nil
}

// Stop stops the Prometheus exporter HTTP server
func (e *PrometheusExporter) Stop() error {
	if e.server != nil {
		return e.server.Close()
	}
	return nil
}

// UpdateMetrics updates the Prometheus metrics based on the current node statuses
func (e *PrometheusExporter) UpdateMetrics() {
	if !e.config.Prometheus.Enabled {
		log.Debug("Prometheus metrics exporter is disabled, skipping metrics update")
		return
	}

	log.Debug("Updating Prometheus metrics...")

	// Get current node statuses
	log.Debug("Calling getNodeStatuses function...")
	statuses := e.getNodeStatuses()
	if statuses == nil {
		log.Error("getNodeStatuses returned nil")
		return
	}

	// Log the number of statuses
	log.Infof("Prometheus exporter: updating metrics with %d node statuses", len(statuses))

	// Debug logging to show actual statuses if present
	if len(statuses) > 0 {
		for instance, status := range statuses {
			log.Debugf("Node status for metrics: instance=%s, peerID=%s, name=%s, healthy=%v, local=%s, online=%v, jailed=%v, apr=%f",
				instance, status.PeerID, status.Name, status.Healthy, status.LocalStatus, status.Online, status.Jailed, status.APR)
		}
	} else {
		log.Warn("No node statuses available for metrics update - check monitor.GetNodeStatuses()")
	}

	// Update metrics for each node
	for instance, status := range statuses {
		if status == nil {
			log.Warnf("Found nil status for instance %s, skipping", instance)
			continue
		}

		labels := prometheus.Labels{
			"instance": status.Instance,
			"peer_id":  status.PeerID,
			"name":     status.Name,
		}

		// APR
		e.nodeAPR.With(labels).Set(status.APR)
		log.Debugf("Set APR metric for %s: %f", status.Instance, status.APR)

		// Jailed status
		jailedLabels := prometheus.Labels{
			"instance": status.Instance,
			"peer_id":  status.PeerID,
			"name":     status.Name,
			"reason":   status.JailedReason,
		}
		if status.Jailed {
			e.nodeJailed.With(jailedLabels).Set(1)
			log.Debugf("Set jailed metric for %s: 1", status.Instance)
		} else {
			e.nodeJailed.With(jailedLabels).Set(0)
			log.Debugf("Set jailed metric for %s: 0", status.Instance)
		}

		// Online status
		if status.Online {
			e.nodeOnline.With(labels).Set(1)
			log.Debugf("Set online metric for %s: 1", status.Instance)
		} else {
			e.nodeOnline.With(labels).Set(0)
			log.Debugf("Set online metric for %s: 0", status.Instance)
		}

		// Local status
		localStatusLabels := prometheus.Labels{
			"instance": status.Instance,
			"peer_id":  status.PeerID,
			"name":     status.Name,
			"status":   status.LocalStatus,
		}
		if status.LocalStatus == "running" {
			e.nodeLocalStatus.With(localStatusLabels).Set(2)
			log.Debugf("Set local status metric for %s: 2 (running)", status.Instance)
		} else if status.LocalStatus == "stopped" {
			e.nodeLocalStatus.With(localStatusLabels).Set(1)
			log.Debugf("Set local status metric for %s: 1 (stopped)", status.Instance)
		} else {
			e.nodeLocalStatus.With(localStatusLabels).Set(0)
			log.Debugf("Set local status metric for %s: 0 (failed)", status.Instance)
		}

		// Healthy status
		if status.Healthy {
			e.nodeHealthy.With(labels).Set(1)
			log.Debugf("Set healthy metric for %s: 1", status.Instance)
		} else {
			e.nodeHealthy.With(labels).Set(0)
			log.Debugf("Set healthy metric for %s: 0", status.Instance)
		}

		// Last restart timestamp
		if !status.LastRestart.IsZero() {
			e.lastRestart.With(labels).Set(float64(status.LastRestart.Unix()))
			log.Debugf("Set last restart metric for %s: %d", status.Instance, status.LastRestart.Unix())
		}
	}

	// Force a metrics collection to ensure the metrics are exposed
	if _, err := e.registry.Gather(); err != nil {
		log.Errorf("Error gathering metrics: %v", err)
	}

	log.Info("Prometheus metrics update completed")
}
