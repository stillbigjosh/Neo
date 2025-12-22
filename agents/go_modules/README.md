# Modular Go Agent Features

This directory contains the modular structure for the Go agent, allowing operators to include or exclude specific features to reduce payload size while maintaining core functionality.

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
- Commands: `bof <base64_encoded_bof> [args]`

#### .NET Assembly Execution
- Path: `go_modules/assembly/`
- Function: Execute .NET assemblies in memory
- Dependencies: github.com/Ne0nd0g/go-clr
- Commands: `assembly <base64_encoded_assembly>`

#### Shellcode Injection
- Path: `go_modules/shellcode/`
- Function: Inject and execute shellcode in target processes
- Commands: `shellcode <base64_encoded_shellcode>`

#### PE Injection
- Path: `go_modules/pe/`
- Function: Inject and execute PE files in target processes
- Commands: `peinject pe<base64_encoded_pe>`

#### Reverse Proxy
- Path: `go_modules/reverse_proxy/`
- Function: SOCKS5 proxy functionality
- Commands: `reverse_proxy_start`, `reverse_proxy_stop`

#### Sandbox Detection
- Path: `go_modules/sandbox/`
- Function: Anti-analysis and evasion checks
- Commands: Automatically executed during registration

## Usage

When generating payloads, operators can specify which features to include:

```python
# Include all features (default)
generate_payload(listener_id, "go_agent", include_bof=True, include_assembly=True, include_pe=True, include_shellcode=True, include_reverse_proxy=True, include_sandbox=True)

# Exclude specific features to reduce size
generate_payload(listener_id, "go_agent", include_bof=False, include_assembly=False)

# Minimal payload with only core functionality
generate_payload(listener_id, "go_agent", include_bof=False, include_assembly=False, include_pe=False, include_shellcode=False, include_reverse_proxy=False, include_sandbox=False)
```

## Benefits

- **Reduced Payload Size**: Excluding features significantly reduces binary size
- **Faster Compilation**: Fewer dependencies and code to compile
- **Evasion**: Smaller, simpler payloads may evade detection better
- **Flexibility**: Operators choose only needed capabilities
- **Maintainability**: Modular code is easier to maintain and update