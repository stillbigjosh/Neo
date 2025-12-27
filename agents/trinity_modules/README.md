# Modular Trinity Agent Features

This directory contains the modular structure for the Trinity agent, allowing operators to include or exclude specific features to reduce payload size while maintaining core functionality.

## Feature Modules

### Core Module
- Essential C2 communication
- Basic command execution
- Registration and task handling
- Encryption/decryption
- Failover support
- Working hours and kill date enforcement

### Advanced Feature Modules

#### BOF (Beacon Object File) Execution
- Path: `go_modules/bof/`
- Function: Execute COFF files in memory
- Dependencies: github.com/praetorian-inc/goffloader

#### .NET Assembly Execution
- Path: `go_modules/assembly/`
- Function: Execute .NET assemblies in memory
- Dependencies: github.com/Ne0nd0g/go-clr

#### Shellcode Injection
- Path: `go_modules/shellcode/`
- Function: Inject and execute shellcode in target processes

#### PE Injection
- Path: `go_modules/pe/`
- Function: Inject and execute PE files in target processes

#### Reverse Proxy
- Path: `go_modules/reverse_proxy/`
- Function: SOCKS5 proxy functionality
- Commands: `reverse_proxy_start`, `reverse_proxy_stop`

#### Sandbox Detection
- Path: `go_modules/sandbox/`
- Function: Anti-analysis and evasion checks

---
