# Agent Management

## Agent Lifecycle

Agents in NeoC2 follow a complete lifecycle:
1. **Registration**: Agents connect and register with the C2
2. **Heartbeat**: Regular check-ins to maintain connection
3. **Tasking**: Receive and execute commands
4. **Results**: Send back execution output
5. **Interaction**: Real-time command execution
6. **Termination**: Removal from management

## Agent Commands

```
agent list                    # List all active agents
agent interact <agent_id>     # Enter interactive mode with agent
agent info <agent_id>         # Get detailed agent information
agent kill <agent_id>         # Remove agent from management
```

## Agent Status Indicators

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