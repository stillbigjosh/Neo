
# File Operations

NeoC2 provides enhanced file operations with automatic handling of encoded content.

### File Download
- Files are automatically base64-encoded during transfer
   `download <agent_id> <remote_file_path>` - queues download task for the agent
- The command-and-control automatically detects and decodes base64 content for storage on C2's machine
- Downloaded Files saved to loot directory with timestamps and sanitized names
- Remote clients can also `download <server_file_path>` an agent executable or script from C2 Server to your local remote_client machine mid-operation. This is a restricted command which requires higher operator role.

### File Upload
- Local files are automatically base64-encoded before transmission to agent
- `upload [agent_id] <local_file_path> <remote_file_path>` - agent receives and decodes the file
- CLI Integration: Use the `upload` command to send files to agents

### Save
- `save <task_id>` - Saves the complete result from given task id
- Files ae stored on the server logs directory.
- Download to your connected client machine using `download <path>`

**Example Usage**:
```
# Agent ID is automatically inferred in interactive mode
# Download a file from the agent
download [agent_id] <remote_file_path>
download c:\users\testuser\file.xml

# Download a file from the C2 Server
download <file_path_on_c2>

# Upload a file to the agent
upload [agent_id] <local_file_path> <remote_file_path>
upload /path/to/file.xml c:\users\testuser\file.xml

# Save a task result to c2 and download to local machine
save <task_id>
save 2
download logs/task_2_20251128_224240.txt
```

