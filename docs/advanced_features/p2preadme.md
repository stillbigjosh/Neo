# P2P

## Agent 

- Phantom Hawk.

## Key Features

### 1. Network Discovery
- **Automatic Agent Discovery**: Agents automatically scan the local network to find other NeoC2 agents
- **TCP Port Scanning**: Discovers agents on configurable ports (default range around port 8888)
- **UDP Broadcast Discovery**: Uses UDP broadcasts to identify agents on the same network segment
- **Agent Registry**: Maintains an internal registry of discovered agents with their IDs and hostnames

### 2. Command Forwarding
- **Direct Command Execution**: Forward commands to other agents without C2 server involvement
- **Bidirectional Communication**: Agents can send and receive forwarded commands
- **Real-time Results**: Immediate return of command results from target agents

### 3. Configurable Architecture
- **Profile-Based Configuration**: P2P functionality enabled/disabled via agent profiles
- **Customizable Port**: Configurable P2P communication port (default: 8888)
- **Toggle On/Off**: P2P capabilities can be completely disabled for stealth operations

### 4. Integrated Command Interface
- **p2p list**: Display all discovered agents on the network
- **p2p forward <addr:port> <command>**: Forward a command to another agent
- **p2p discover**: Manually trigger agent discovery process

## Architecture

### Discovery Process
1. **Port Scanning**: Scans nearby ports (±5 range) around configured P2P port
2. **Connection Testing**: Attempts TCP connections to discovered ports
3. **Handshake Protocol**: Exchanges agent identity information using JSON messages
4. **Broadcast Discovery**: Sends UDP broadcasts to `<broadcast>:8888` to discover agents on same subnet
5. **Registry Maintenance**: Updates internal agent registry with discovered agents

### Communication Protocol
- **JSON-based messaging** for standardized P2P communication
- **Message Types**: 
  - `discovery` - Initial agent presence announcement
  - `discovery_response` - Response to discovery requests
  - `command_forward` - Forwarded command execution request
- **Threaded Server**: Each incoming connection handled in separate thread to prevent blocking

### Configuration Schema
```json
{
  "p2p_enabled": true,
  "p2p_port": 8888
}
```

## Usage Guide

### 1. Profile Configuration

To enable P2P functionality, configure the agent profile with P2P settings:

```
# In profile configuration
{
  "p2p_enabled": true,
  "p2p_port": 8888,
  "protocol": "http",
  "heartbeat_interval": 60,
  "jitter": 0.2,
  ...
}
```

### 2. Basic Commands

After P2P functionality is enabled and agents are deployed:

**List discovered agents:**
```
p2p list
```
Output example:
```
[P2P AGENTS]
Agent: 550e8400-e29b-41d4-a716-446655440000, Hostname: DC01, Addr: 192.168.1.10:8888
Agent: 6ba7b810-9dad-11d1-80b4-00c04fd430c8, Hostname: WORKSTATION05, Addr: 192.168.1.15:8888
```

**Forward a command to another agent:**
```
p2p forward 192.168.1.15:8888 whoami
```
Output example:
```
WORKSTATION05\user
```

**Manual discovery:**
```
p2p discover
```
```
[P2P] Discovery initiated
```

### 3. Advanced Operations

**Execute PowerShell on remote agent:**
```
p2p forward 192.168.1.15:8888 powershell -c "Get-Process | Select-Object -First 5 | ConvertTo-Json"
```

**Run modules on remote agents:**
```
p2p forward 192.168.1.15:8888 module <base64_encoded_module_script>
```

**Check network connectivity:**
```
p2p forward 192.168.1.15:8888 ping -c 4 192.168.1.20
```

## Configuration Options

### Profile Configuration
```json
{
  "p2p_enabled": true,           // Enable/disable P2P functionality (default: false)
  "p2p_port": 8888,              // P2P communication port (default: 8888)
  "heartbeat_interval": 60,      // Standard C2 heartbeat
  "jitter": 0.2,                 // Standard C2 jitter
  ...
}
```

P2P IS STILL UNDER DEVELOPMENT. DO NOT USE IN REAL RED TEAM ENGAGEMENTS
