# SQD Agent

A monitoring and management agent for SQD nodes running on Linux servers.

## Features

- Written in Go
- Runs as a systemd service on Linux systems
- Monitors multiple SQD nodes on each server
- Uses SQD GraphQL API to get node information (APR, online status, jailed status, etc.)
- Uses custom commands to discover and manage SQD nodes
- Supports notifications via webhooks and Discord
- Exposes Prometheus metrics for monitoring
- Auto-updates to the latest version

## Installation

### From Source

1. Clone the repository:
   ```
   git clone https://github.com/nodexeus/sqd-agent.git
   cd sqd-agent
   ```

2. Build and install:
   ```
   make install
   ```

3. Enable and start the service:
   ```
   systemctl enable --now sqd-agent
   ```

### Using Debian Package

1. Download the latest `.deb` package from the releases page.

2. Install the package:
   ```
   sudo dpkg -i sqd-agent_*.deb
   ```

3. Enable and start the service:
   ```
   systemctl enable --now sqd-agent
   ```

## Configuration

The configuration file is located at `/etc/sqd-agent/config.yaml`. Here's an example configuration:

```yaml
# General settings
logLevel: "info"
monitorPeriod: "5m"  # How often to check node status
actionPeriod: "6h"   # How often to take action on unhealthy nodes
passiveMode: false   # If true, only monitor and don't take actions
autoUpdate: true     # Automatically update the agent when new versions are available

# Notification settings
notifications:
  enabled: true
  webhookEnabled: false
  webhookUrl: "https://example.com/webhook"
  discordEnabled: false
  discordWebhooks:
    - name: "alerts"
      url: "https://discord.com/api/webhooks/your-webhook-url"

# Prometheus metrics settings
prometheus:
  enabled: true
  port: 9090
  path: "/metrics"

# GraphQL API settings
graphql:
  endpoint: "https://your-graphql-endpoint.com"

# Custom commands
commands:
  discoverNodes: "apptainer instance list -j | jq -r '.instances[]| .instance'"
  getNodePeerID: "bv node run address"
  restartNode: "bv node restart"
  getNodeStatus: "bv node status"
```

## Prometheus Metrics

When enabled, the agent exposes the following metrics on the configured port:

- `sqd_node_apr`: Annual Percentage Rate (APR) of the SQD node
- `sqd_node_jailed`: Whether the SQD node is jailed (1) or not (0)
- `sqd_node_online`: Whether the SQD node is online (1) or not (0)
- `sqd_node_local_status`: Local status of the SQD node (1=running, 0=not running)
- `sqd_node_healthy`: Whether the SQD node is healthy (1) or not (0)
- `sqd_node_last_restart_timestamp`: Timestamp of the last restart attempt for the SQD node

## Node Health Criteria

A node is considered healthy if all of the following conditions are met:
- Local status is "running"
- Network status is "online"
- Not jailed
- APR is greater than 0

If any of these conditions are not met, the node is considered unhealthy and will be restarted according to the configured action period.

## Development

### Prerequisites

- Go 1.16 or later
- Make

### Building

```
make build
```

### Testing

```
make test
```

### Creating a Debian Package

```
make deb
```

## License

[GPL-3.0 License](LICENSE)

## Hosting

[![Hosted By: Cloudsmith](https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=for-the-badge)](https://cloudsmith.com)

Package repository hosting is graciously provided by  [Cloudsmith](https://cloudsmith.com).
Cloudsmith is the only fully hosted, cloud-native, universal package management solution, that
enables your organization to create, store and share packages in any format, to any place, with total
confidence.
