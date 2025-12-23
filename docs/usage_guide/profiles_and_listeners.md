# Profile & Listener Management

## Profile Management

Profiles define communication characteristics for agents:

### Profile Structure

```json
{
  "name": "my_https_profile",
  "description": "Custom HTTPS communication profile",
  "config": {
    "endpoints": {
      "download": "/api/assets/main.js",
      "register": "/api/users/register",
      "results": "/api/users/{agent_id}/activity",
      "tasks": "/api/users/{agent_id}/profile",
      "interactive": "/api/users/{agent_id}/settings",
      "interactive_status": "/api/users/{agent_id}/status"
    },
    "headers": {
      "Accept": "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    },
    "heartbeat_interval": 10,
    "http_get": {
      "headers": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      },
      "uri": "/api/v1/info"
    },
    "http_post": {
      "headers": {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      },
      "uri": "/api/v1/submit"
    },
    "jitter": 0.2,
    "protocol": "https",
    "p2p_enabled": false,
    "p2p_port": 8888,
    "kill_date": "2027-12-31T23:59:59Z",
    "working_hours": {
      "start_hour": 0,
      "end_hour": 24,
      "timezone": "UTC",
      "days": [1, 2, 3, 4, 5, 6, 7]
    },
    "redirector": {
      "redirector_host": "0.0.0.0",
      "redirector_port": 80
    },
    "failover_urls": [
      "https://failover1.example.com:443",
      "https://failover2.example.com:443",
      "https://backup1.example.com:8443",
      "https://backup2.example.com:8443"
    ]
  }
}

```
#### Endpoints

- `endpoints.register`: Used by the agent to register itself with the C2 server

- `endpoints.tasks`: Used by the agent to retrieve queued tasks assigned to it, where {agent_id} is replaced with the actual agent identifier

- `endpoints.results`: Used by the agent to submit the results of executed tasks back to the C2 server

- `endpoints.interactive`: Used for interactive command functionality - the agent bypasses queued tasks, retrieves interactive commands and submits interactive command results through this endpoint

- `endpoints.interactive_status`: Used by the agent to check the interactive mode status to determine if it should operate in interactive mode or normal task mode


#### Kill Date Configuration

- **Field**: `kill_date`
- **Format**: ISO 8601 format in UTC timezone (`YYYY-MM-DDTHH:MM:SSZ`)
- **Example**: `"2027-12-31T23:59:59Z"`
- **Default**: If not specified, defaults to `"2027-12-31T23:59:59Z"`
- **Behavior**: When the agent's system time exceeds this date/time, the agent will self-delete

#### Working Hours Configuration

- **Field**: `working_hours`
- **Structure**:
  - `start_hour`: Start of working hours (0-23 in 24-hour format)
  - `end_hour`: End of working hours (0-23 in 24-hour format)
  - `timezone`: Timezone for working hours (currently only UTC is properly handled in the agent)
  - `days`: Array of days when working hours apply (1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday, 7=Sunday)

**Example**:
```json
"working_hours": {
  "start_hour": 9,      // 9 AM
  "end_hour": 17,       // 5 PM
  "timezone": "UTC",    // Timezone
  "days": [1, 2, 3, 4, 5]  // Monday to Friday
}
```

1. Both kill date and working hours are embedded into the agent binary during generation and are not dynamically updated from the server during runtime.
2. Changes to the profile after agent deployment will NOT affect already deployed agents.
3. The agent currently handles UTC properly, but other timezones are primarily handled as local time.
4. Days are numbered from 1-7 (Monday=1, Sunday=7), with Sunday represented as both 0 (Go's default) and 7 (in configuration).
5. Hours are specified in 24-hour format (0-23).

#### Redirector

1. Add redirector settings to your C2 profile under the redirector key:

```json
 "redirector": {
      "redirector_host": "0.0.0.0",
      "redirector_port": 80
    }

```

2. How it works:

Use the --redirector flag when generating payloads:

- Without `--redirector`: Agent connects directly to C2 server

- With `--redirector`: Agent connects to the redirector host/port specified in the profile instead of the C2 server
  
- All other agent behavior remains the same

#### Failover deployment

1. Add backup failover Neo C2 Servers to profile config:

```json
"failover_urls": [
      "https://failover1.example.com:443",
      "https://failover2.example.com:443",
      "https://backup1.example.com:8443",
      "https://backup2.example.com:8443"
    ]
```

2. How it works:

CLI Support: `--use-failover` flag correctly during payload generation

- Agents maintain connection to primary C2 with failure counting

- Upon reaching failure threshold `15`, agents attempt to connect to failover servers in sequence

- Success with any failover server becomes new current C2

- Automatic reset and failback mechanisms

Without `--use-failover` flag, Agents are generated without embedded failover servers

3. Agent Key Distribution for Failover Setup:

To enable agents to communicate with failover C2 servers, you need to share agent secret keys between primary and failover servers using the new failover commands:

**Export Agent Keys from Primary C2:**

```bash
# Export all agent keys
failover export-keys /path/to/agent_keys.json

# Export specific agent key
failover export-keys /path/to/single_agent.json AGENT123
```

**Import Agent Keys to Failover C2:**

```bash
# Import agent keys to failover server
failover import-keys /path/to/agent_keys.json
```

This creates a secure distribution file containing agent IDs and their secret keys that can be safely transferred between C2 servers. Once imported on the failover server, agents can authenticate and communicate with the failover C2 using their existing secret keys without requiring manual database operations.

### Load Profile to DB

Load a config using the `profile` handler and base-command:

```bash
profile add <config path>
# Register profile routes
listener create <listener_name> https <port> <ip> profile_name=<profile_name>
```

### List avaiable Profiles

List all available profiles in DB

```bash
profile list
```

### Reload existing Profiles

- During framework initialization, the default profile is automatically written to profiles/default.json
- Operators can make any changes to this json config and apply the changes by reloading the profile with changes using:
```bash
profile reload <profile_path> <profile_name>
```
- The reload command can be used for any custom profile, and the default profile

## Listener Management

HTTPS listeners(which are the supported listener type) run as separate processes from the main Flask application, acting as internal redirectors, forwarding traffic from agents to the main web interface. Listeners in NeoC2 are profile-driven: they use predefined communication profiles.

### Listener Commands

```
# Type should be HTTPS
listener create <name> <type> <port> [profile_name=<profile>]
listener list
listener start <name>
listener stop <name>
listener delete <name>
```

### Profile Integration

When creating a listener, you associate it with a communication profile:
```
listener create my_http_listener type=https port=443 profile_name=stealth_crawler
```

