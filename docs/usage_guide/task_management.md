# Task Management

Tasks are commands executed on an active agent session. NeoC2 implements a sophisticated task management system that distinguishes between two primary execution modes: **Queued Tasks** and **Interactive Tasks**. 
- Queued tasks are stored in the database and retrieved by agents during their regular polling cycles for asynchronous execution, allowing for reliable command delivery and result storage.
- Interactive tasks, on the other hand, bypass the standard queue and communicate directly with agents in real-time when an operator is in an interactive session, providing immediate command execution and response feedback.

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

