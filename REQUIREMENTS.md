## Agent Features:
- Written in Go
- Runs via systemd on linux systems
- monitors multiple sqd nodes on each server
- Uses sqd GraphQL API to get node information (apr, online status, jailed status, jailed Reason, and more)
- Uses a config file in /etc/sqd-agent/config.yaml to determine certain settings such as push notifications, notification webhook url, run in a passive mode where it reports but doesn't take action, enable prometheus metrics, auto update, monitor period (how often to check the nodes), action period (how often to take action)
- Uses custom commands to dynamically discover all the sqd nodes on the server
- Uses custom commands to take action on the sqd nodes (restart, etc)
- Monitors the sqd node local status as well as network status.  Local status is discovered via custom commands, network status is discovered via the sqd GraphQL API
- Supports sending notifications via json webhook, discord, and a health metric made available as part of the prometheus metrics
- Supports an auto-update feature that will update the agent to the latest version when available

## Custom Commands:
- discover running nodes: apptainer instance list -j | jq -r '.instances[]| .instance' (will return a list of running instances)
- get node peer id: bv node run address <instance> (will return the peer id of the node)
- restart node: bv node restart <instance> (will restart the node)
- get node status: bv node status <instance> (will return the status of the node)
- graphql endpoint to use: https://<to be provided>
- graphql query to use to get apr, online status, jailed status, jailed reason, and more: <to be provided>
