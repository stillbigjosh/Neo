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
- **Module Execution Capability**: Runs extensible modules from C2
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment
- **Working hours & Kill dates**: The Go-agent incorporates a profile configurable kill-dates and working-hours restrictions
- **Process Injection**: Shellcode injection into notepad.exe or explorer.exe with pinject
- **Redirector Support**: Supports using a rediector address for operational security

### Limitations
- Larger payload size due to comprehensive feature set

### Usage
```
NeoC2 > payload go_agent <listener_name> [--disable-sandbox] [--windows] [--redirector]
NeoC2 [INTERACTIVE:abc123] > [upload, download, tty_shell, pinject, sleep, kill, interact, run]
```


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
- **Module Execution Capability**: Runs extensible modules from C2
- **P2P Agent Communication**: Configurable Agent command forwarding to other Agents in same network (Under development)
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment

### Limitations
- No working hours/kill-date support
- It doesn't support process injection 
- No redirector support (yet)

### Usage
```
NeoC2 > payload phantom_hawk <listener_id> [--obfuscate] [--disable-sandbox] [--linux]
NeoC2 [INTERACTIVE:abc123] > [upload, download, tty_shell, sleep, kill, interact, run]
```


## Droppers

### Description
**IMPORTANT: These are DROPPERS only** - they download an agent from `/api/assets/main.js`, execute it, and then delete themselves. They do NOT contain interactive capabilities or command execution features. These are designed purely for initial access and agent deployment.

### Supported Types

#### Bash Dropper
- **Linux compatibility**
- **Downloads agent** from `/api/assets/main.js` endpoint and deryptes using embedded secret key
- **Self-executes** the downloaded agent 
- **Self-deletes** after execution
- **Binary payload support**: Can only execute linux binary files after temporary storage
### Usage
```
stager generate linux_binary host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
```

#### Powershell Dropper
- **Windows compatibility**
- **Downloads agent** from `/api/assets/main.js` endpoint and deryptes using embedded secret key
- **Self-executes** the downloaded agent 
- **Self-deletes** after execution
- **Binary payload support**: Can only execute windows .exe binary files
### Usage
```
stager generate windows_exe host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
```

---

