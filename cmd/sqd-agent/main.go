package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/api"
	"github.com/nodexeus/sqd-agent/pkg/config"
	"github.com/nodexeus/sqd-agent/pkg/discovery"
	"github.com/nodexeus/sqd-agent/pkg/metrics"
	"github.com/nodexeus/sqd-agent/pkg/monitor"
	"github.com/nodexeus/sqd-agent/pkg/notifier"
	"github.com/nodexeus/sqd-agent/pkg/updater"
)

var (
	configPath = flag.String("config", "/etc/sqd-agent/config.yaml", "Path to config file")
	version    = "0.1.0" // This would be set during build
)

func main() {
	flag.Parse()

	// Print version
	fmt.Printf("SQD Agent v%s\n", version)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Printf("Warning: %v", err)
	}

	// Get system hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Warning: failed to get hostname: %v", err)
		hostname = "unknown"
	}
	log.Printf("Running on host: %s", hostname)

	// Create components
	discoverer := discovery.NewDiscoverer(cfg)
	apiClient := api.NewGraphQLClient(cfg)
	mon := monitor.NewMonitor(cfg, discoverer, apiClient)

	// Add notifiers
	if cfg.Notifications.Enabled {
		if cfg.Notifications.WebhookEnabled {
			webhookNotifier := notifier.NewWebhookNotifier(cfg, hostname)
			mon.AddNotifier(webhookNotifier)
		}

		if cfg.Notifications.DiscordEnabled {
			discordNotifier := notifier.NewDiscordNotifier(cfg, hostname)
			mon.AddNotifier(discordNotifier)
		}
	}

	// Create metrics exporter
	var prometheusExporter *metrics.PrometheusExporter
	if cfg.Prometheus.Enabled {
		prometheusExporter = metrics.NewPrometheusExporter(cfg, mon)
		if err := prometheusExporter.Start(); err != nil {
			log.Fatalf("Failed to start Prometheus exporter: %v", err)
		}
	}

	// Create updater
	var upd *updater.Updater
	if cfg.AutoUpdate {
		upd, err = updater.NewUpdater(cfg)
		if err != nil {
			log.Printf("Warning: Failed to create updater: %v", err)
		}
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	if err := mon.Start(ctx); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}

	// Start metrics updater if enabled
	if cfg.Prometheus.Enabled && prometheusExporter != nil {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					prometheusExporter.UpdateMetrics()
				}
			}
		}()
	}

	// Start auto-updater if enabled
	if cfg.AutoUpdate && upd != nil {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()

			// Check for updates immediately on startup
			checkAndUpdate(ctx, upd)

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					checkAndUpdate(ctx, upd)
				}
			}
		}()
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	// Cancel context to stop all components
	cancel()

	// Stop Prometheus exporter if enabled
	if cfg.Prometheus.Enabled && prometheusExporter != nil {
		if err := prometheusExporter.Stop(); err != nil {
			log.Printf("Error stopping Prometheus exporter: %v", err)
		}
	}

	log.Println("Shutdown complete")
}

// checkAndUpdate checks for updates and applies them if available
func checkAndUpdate(ctx context.Context, upd *updater.Updater) {
	releaseInfo, hasUpdate, err := upd.CheckForUpdates(ctx)
	if err != nil {
		log.Printf("Error checking for updates: %v", err)
		return
	}

	if hasUpdate {
		log.Printf("New version available: %s", releaseInfo.Version)
		if err := upd.Update(ctx, releaseInfo); err != nil {
			log.Printf("Error updating: %v", err)
			return
		}
		log.Printf("Update to version %s scheduled for next restart", releaseInfo.Version)
	}
}
