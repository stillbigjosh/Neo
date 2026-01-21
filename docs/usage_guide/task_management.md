# Task Management

Tasks are commands executed on an active agent session. NeoC2 implements a sophisticated task management system that distinguishes between two primary execution modes: **Queued Tasks** and **Interactive Tasks**:

- Queued tasks are stored in the database and retrieved by agents via the regular tasking Queued API, during their regular profile-defined polling cycles for asynchronous execution, allowing for reliable command delivery and result storage.

- Interactive tasks, on the other hand, bypass the standard queue and communicate directly with agents in real-time via the Interactive API, when an operator is in an interactive session, Agent polling increases to 2 seconds, providing immediate command execution and response feedback.

## Task Types and Commands: 

- **Queued Tasks**: An agent id would have to be specified for agent tasking in non-interactive mode of the command-and-control. Agent uses the standard queued api which takes longer than the interactive api. 
```
# Execute shell commands using Queued Tasking
NeoC2 (user@remote) > addcmd <agent_id> <command>

# Execute shell commands using Queued Tasking in Interactive mode
NeoC2 [INTERACTIVE:d2862d54] > addcmd <command> 

# Execute modules using Queued Tasking
NeoC2 (user@remote) > execute-bof <agent_id> [options]
NeoC2 (user@remote) > execute-assembly <agent_id> [options]

# Execute modules using Queued Tasking in Interactive mode
NeoC2 [INTERACTIVE:d2862d54] > execute-bof [options]
NeoC2 [INTERACTIVE:d2862d54] > execute-assembly [options]
```

- **Interactive Tasks**: Direct Real-time command execution in interactive mode. Agent ids are automatically inferred in the interactive mode. Agent uses the fast polling interactive api. Interactive tasks can only be sent in Interactive mode, whereas, Queued tasks can be sent both in interactive mode and standard queued mode.
```
# Execute shell commands Interactive Tasking in Interactive mode
NeoC2 [INTERACTIVE:d2862d54] > cmd <command>

# Execute modules using Interactive Tasking in Interactive mode
NeoC2 [INTERACTIVE:d2862d54] > execute-bof [options]
NeoC2 [INTERACTIVE:d2862d54] > execute-assembly [options]
```

## Task Lifecycle

1. **Creation**: Task added to agent queue
2. **Assignment**: Agent retrieves task
3. **Execution**: Agent executes task
4. **Result Submission**: Agent sends results back
5. **Storage**: Results stored in database
6. **Notification**: Operator notified of completion

## View Pending Tasks

```
# Show pending tasks
NeoC2 (user@remote) > task <agent_id>

# Show pending tasks of the current agent in Interactive mode
NeoC2 [INTERACTIVE:d2862d54] > task
```

## Task Result
- Shows all results from all agents `result list`
- Displays specific agent results `result <agent_id>`
- Shows specific task results with detailed information `result <task_id>`

```
# List agents results
NeoC2 (user@remote) > result list

# List results for a specific agent
NeoC2 (user@remote) > result <agent_id>

# Show result of a specific task id
NeoC2 (user@remote) > result <task_id>

# Show results of the current agent in interactive mode
NeoC2 [INTERACTIVE:d2862d54] > result 
```


