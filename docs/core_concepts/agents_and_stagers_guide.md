# NeoC2 Agent Documentation

## Table of Contents
- [Go Agent](#go-agent)
- [Phantom Hawk Agent](#phantom-hawk-agent)
- [Droppers](#droppers)

---

## Go Agent

### Description
The Go Agent is a second stage exe compiled, multi-functional agent with features like file transfer, interactive mode, and windows powershell/linux based module execution.

### Tested
- Windows x64

### Capabilities
- **Command Execution**: Execute arbitrary shell commands on the target system
- **File Transfer**: Upload and download files using base64 encoding
- **Interactive Mode**: Enter real-time interactive session with the target
- **TTY Shell Enabled**: Enter a full TTY Shell
- **Polymorphic Obfuscation**: Randomized variable and function names to evade static analysis
- **Jitter & Sleep Obfuscation**: Configurable sleep intervals with jitter during agent generation and in deployment
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment
- **Working hours & Kill dates**: The Go-agent incorporates a profile configurable kill-dates and working-hours restrictions
- **Redirector Support**: Allows operators to define and manage external infrastructure that points to the internal listeners
- **Failover deployment**: Embeds failover C2 servers
- **XOR string encryption**: Encrypts DLL imports and Windows API functions strings to evade static analysis and signature-based detection, which typically inspect the Import Address Table (IAT). At runtime, a XOR decryption routine is used to reconstruct the correct names.
- **PowerShell Module Execution**: Runs external powershell modules with `pwsh` 
- **Shellcode Injection**: Shellcode injection into notepad.exe or explorer.exe with `pinject`
- **Process Hollowing**: Unmanaged Portable Executables injection into svchost.exe with `peinject`
- **.NET Assembly Execution**: In-memory execution of .NET Assemblies with `inline-execute-assembly`
- **BOF Execution**: In-memory BOF execution in in own process with no disk writes `inline-execute`

### Limitations
- Larger payload size due to comprehensive feature set

### Usage
```
NeoC2 > payload go_agent <listener_name> [--disable-sandbox] [--windows] [--redirector] [--use-failover] [--obfuscate]
NeoC2 [INTERACTIVE:abc123] > [pwsh, pinject, peinject, inline-execute, inline-execute-assembly, upload, download, tty_shell, sleep, kill, interact, run]
```

### Additional note
The secret key used for string encrytion is a simple XOR key with the value 0x42 (66 in decimal) at default. This key is defined in the Go agent template. This key is used in the runtime deobfuscation where each byte of the obfuscated string is XORed with this key to get the original string back. 
However, To override this default key, ensure you use `--obfuscate` during payload generation, it randomizes this key and randomizes obfuscated bytes to make each agent unique.

## Phantom Hawk Agent 

### Description
Phantom Hawk is a Python variant with limited capability.

### Tested
- Windows x64 (Compile to exe on a Windows host)
- Linux Debian

### Capabilities
- **Command Execution**: Execute arbitrary shell commands on the target system
- **Anti Debugging, Sandbox Detection & Self Deletion**: Works on Windows, Linux Hosts. 
- **File Transfer**: Upload and download files using base64 encoding
- **Interactive Mode**: Enter real-time interactive session with the target
- **TTY Shell Enabled**: Enter a full TTY Shell 
- **Polymorphic Obfuscation**: Randomized variable and function names to evade static analysis
- **Jitter & Sleep Obfuscation**: Configurable sleep intervals with jitter during agent generation and in deployment
- **Cross-Platform**: Works on Windows, Linux 
- **P2P Agent Communication**: Configurable Agent command forwarding to other Agents in same network (Under development)
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

