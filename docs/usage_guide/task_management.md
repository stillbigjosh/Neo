# Task Management

Tasks are commands executed on an active agent session. NeoC2 implements a sophisticated task management system:

## Task Types

1. **Queued Tasks**: Standard command execution
2. **Interactive Tasks**: Real-time command execution
3. **Download Tasks**: File retrieval operations
4. **Upload Tasks**: File transfer to agents
5. **Module Tasks**: Specialized module execution

## Task Lifecycle

1. **Creation**: Task added to agent queue
2. **Assignment**: Agent retrieves task
3. **Execution**: Agent executes task
4. **Result Submission**: Agent sends results back
5. **Storage**: Results stored in database
6. **Notification**: Operator notified of completion

## Task Commands

```
task <agent_id>                     # Show pending tasks
addtask <agent_id> <command>  # Add task to agent queue
```

## Task Result
- Shows all results from all agents `result list`
- Displays specific agent results `result <agent_id>`
- Shows specific task results with detailed information `result <task_id>

```
result list
result <agent_id>
result <agent_id> <task_id>
```

## File Operations

NeoC2 provides enhanced file operations with automatic handling of encoded content.

### File Download
- Files are automatically base64-encoded during transfer
   `download <remote_path>` - queues download task for the agent
- The command-and-control automatically detects and decodes base64 content for storage on C2's machine
- Downloaded Files saved to loot directory with timestamps and sanitized names
- Remote clients can also `download <logs_path_on_c2>` an agent executable or script from C2 Server to your local remote_client machine mid-operation.

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

## Event Monitoring

All C2 operations are logged. This information can be retrieved using the event handler:

```
event
event list
event search
event stats
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