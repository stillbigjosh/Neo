# NeoC2 Agents and Stagers Guide

## Table of Contents
- [Go Agent](#go-agent)
- [Phantom Hawk Agent](#phantom-hawk-agent)
- [Droppers](#droppers)

---

## Go Agent

The Go Agent is a Windows-based, feature-rich payload designed for advanced operations. It is compiled to a native executable and provides extensive capabilities for post-exploitation activities.

### Architecture

The Go Agent is built with a modular architecture that allows operators to customize the payload size and functionality by including or excluding specific features. This architecture separates core C2 functionality from advanced features, enabling operators to create lightweight payloads when advanced capabilities are not needed.

#### Core Components
- **Communication Layer**: Handles registration, task retrieval, and result submission
- **Command Execution**: Basic command execution capabilities
- **Encryption**: Fernet-based encryption for secure communications
- **Failover Support**: Automatic failover to backup C2 servers
- **Working Hours & Kill Date**: Schedule-based execution controls
- **Sandbox Detection**: Basic evasion checks (when enabled)

#### Advanced Feature Modules
The agent supports the following modular features that can be selectively included:

1. **BOF (Beacon Object File) Execution**
   - Execute COFF files in memory
   - Commands: `execute-bof <bof_filename> [arguments] [agent_id=<agent_id>]`

2. **.NET Assembly Execution**
   - Execute .NET assemblies in memory
   - Commands: `execute-assembly <assembly_filename> [agent_id=<agent_id>]`

3. **Shellcode Injection**
   - Inject and execute shellcode in target processes
   - Multiple injection techniques (NtQueueApcThread, NtCreateThreadEx, CreateRemoteThread, etc.)
   - Commands: `pinject <b64_shellcode_filename> [agent_id=<agent_id>]`

4. **PE Injection**
   - Inject and execute PE files in target processes
   - Process hollowing techniques
   - Commands: `peinject <pe_filename> [agent_id=<agent_id>]`

5. **Reverse Proxy (SOCKS5)**
   - Built-in SOCKS5 proxy functionality
   - Provides pivoting capabilities
   - Commands: `reverse_proxy_start`, `reverse_proxy_stop`

6. **Enhanced Sandbox Detection**
   - Advanced anti-analysis and evasion checks
   - Process monitoring, network tools detection, debugger checks
   - Automatically runs during registration

### Feature Flags

The Go Agent supports feature exclusion flags to reduce payload size and complexity:

#### Available Exclusion Flags

- `--no-bof`: Excludes Beacon Object File execution capability
- `--no-assembly`: Excludes .NET assembly execution capability
- `--no-pe`: Excludes PE injection capability
- `--no-shellcode`: Excludes shellcode injection capability
- `--no-reverse-proxy`: Excludes reverse proxy (SOCKS5) capability
- `--no-sandbox`: Excludes advanced sandbox detection capability

#### Usage Examples

**Default agent with all features:**
```
payload go_agent web_app_default
```

**Agent excluding BOF execution:**
```
payload go_agent web_app_default --no-bof
```

**Agent excluding multiple features:**
```
payload go_agent web_app_default --no-bof --no-assembly --no-pe
```

**Agent with all advanced features excluded:**
```
payload go_agent web_app_default --no-bof --no-assembly --no-pe --no-shellcode --no-reverse-proxy --no-sandbox
```

### Payload Generation

The payload generation process uses a modular approach where the final agent is assembled from separate Go source files based on selected features. This approach provides several benefits:

1. **Reduced Payload Size**: Excluding features significantly reduces the final executable size
2. **Faster Compilation**: Fewer dependencies and code to compile
3. **Evasion**: Smaller, simpler payloads may evade detection better
4. **Flexibility**: Operators can choose only the capabilities needed
5. **Maintainability**: Modular code is easier to maintain and update

### Command Support

The agent's command processing is dynamically adjusted based on included features:

- **Core Commands** (always available):
  - `pwsh <powershell_filename` - Execute powershell scripts in-memory
  - `download <path>` - Download files from the target
  - `upload <path> <data>` - Upload files to the target
  - `sleep <seconds>` - Change agent check-in interval
  - `kill` - Self-delete the agent
  - Direct command execution (shell commands)

- **Feature-Specific Commands** (available when feature is included):
  - `execute-bof <bof_filename> [arguments] [agent_id=<agent_id>]` - Execute BOF (when BOF feature included)
  - `execute-assembly <assembly_filename> [agent_id=<agent_id>]` - Execute .NET assembly (when assembly feature included)
  - `pinject <b64_shellcode_filename [agent_id=<agent_id>]` - Inject shellcode (when shellcode feature included)
  - `peinject <pe_filename> [agent_id=<agent_id>]` - Inject PE file (when PE feature included)
  - `reverse_proxy_start/stop` - Control SOCKS5 proxy (when reverse proxy feature included)

When a feature is excluded, attempting to use its commands will return an appropriate error message indicating that the capability is not available in the current agent build.

### Dependencies

The modular approach conditionally includes external dependencies based on selected features:

- **Core**: github.com/fernet/fernet-go
- **BOF**: github.com/praetorian-inc/goffloader/src/coff and lighthouse
- **Assembly**: github.com/Ne0nd0g/go-clr
- **All other functionality** uses Go's standard library and Windows syscalls

### Security Considerations

- **Polymorphic Engine**: Function and variable names are randomized for each payload
- **String Obfuscation**: Critical strings are obfuscated to evade static analysis
- **Import Obfuscation**: Windows API function names are obfuscated at runtime
- **Size Reduction**: Excluding features reduces the attack surface and detection surface

### Performance Impact

Feature exclusion provides the following benefits:
- **Smaller file size**: Reduced from ~6.5MB (full features) to ~4-5MB (minimal features)
- **Faster compilation**: Less code and dependencies to process
- **Reduced memory footprint**: Fewer loaded modules and functions
- **Simpler execution**: Fewer checks and capabilities to process


## Phantom Hawk Agent 

### Description
Phantom Hawk is a Python variant with limited capability.

### Tested
- Windows x64 (Compile to exe on a Windows host)
- Linux Debian

### Capabilities
- **Proxy Awareness**: Supports Network pivoting using its built-in SOCKS5 proxy
- **Command Execution**: Execute arbitrary shell commands on the target system
- **Anti Debugging, Sandbox Detection & Self Deletion**: Works on Windows, Linux Hosts. 
- **File Transfer**: Upload and download files using base64 encoding
- **Interactive Mode**: Enter real-time interactive session with the target
- **TTY Shell Enabled**: Enter a full TTY Shell 
- **Polymorphic Obfuscation**: Randomized variable and function names to evade static analysis
- **Jitter & Sleep Obfuscation**: Configurable sleep intervals with jitter during agent generation and in deployment
- **Cross-Platform**: Works on Windows, Linux 
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment
- **Working hours & Kill dates**: Incorporates a profile configurable kill-dates and working-hours restrictions
- **Redirector Support**: Allows operators to define and manage external infrastructure that points to the internal listeners
- **Failover deployment**: Embeds failover C2 servers
- **PowerShell Module Execution**: Runs external powershell modules with `pwsh` 

### Limitations
- Lightweight and doesn't pack advanced feature-set

### Usage
```
NeoC2 > payload phantom_hawk <listener_id> [--obfuscate] [--disable-sandbox] [--linux] [--redirector] [--use-failover]
NeoC2 [INTERACTIVE:abc123] > [pwsh, upload, download, tty_shell, sleep, kill, interact, run]
```


## Droppers

### Description
**IMPORTANT: These are DROPPERS only** - they download an agent from the default payload staging API `/api/assets/main.js`, XOR decrypts, execute the implant, and then delete themselves. They do NOT contain interactive capabilities or command execution features. These are designed purely for initial access and agent deployment. 
For seamless operation, use the `payload_upload` feature to stage payloads first, the stager will do the rest. 

### Supported Types

#### Bash Dropper
- **Linux compatibility**
- **Downloads agent** from `/api/assets/main.js` endpoint and XOR derypts using embedded secret key
- **Executes** the downloaded agent 
- **Self-deletes** after execution
- **Binary payload support**: Can only execute linux binary files after temporary storage
### Usage
```
stager generate linux_binary host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
```

#### Powershell Dropper
- **Windows compatibility**
- **Downloads agent** from `/api/assets/main.js` endpoint and XOR derypts using embedded secret key
- **Executes** the downloaded agent 
- **Self-deletes** after execution
- **Binary payload support**: Can only execute windows .exe binary files
### Usage
```
stager generate windows_exe host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
```

---
