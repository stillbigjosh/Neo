# Security & Evasion

## Evasion Techniques

NeoC2 implements multiple evasion techniques to bypass endpoint security:

### Built-in Evasion Methods

1. AMSI Bypass: Anti-Malware Scan Interface bypass
2. ETW Bypass: Event Tracing for Windows disablement

### Evasion Commands
Ensure C2 is in interactive mode before running evasion modules
```
interact <agent_id>
evasion enable <technique>     # Enable specific evasion technique
evasion disable <technique>    # Disable specific evasion technique
evasion list                  # List available evasion techniques
```

## Security Features

### Password Security

- **Secure Hashing**: All passwords hashed using Werkzeug security functions
- **Strong Requirements**: Support for complex password policies
- **Default Credentials**: Stored as secure hashes, not plain text

### Access Control

NeoC2 implements role-based access control:

1. **Admin Role**: Full access to all framework features
2. **Operator Role**: Manage agents, execute modules, handle listeners
3. **Viewer Role**: Read-only access to monitoring and reports

### Session Security

- **Secure Sessions**: Proper session management with authentication
- **Session Timeout**: Automatic logout after inactivity
- **Audit Logging**: Track all user actions and system events

### Encrypted Comms

Robust encrypted communication between agents and the C2 server using Fernet's AES-128-CBC, ensuring that only legitimate agents can register and communicate with the server, while all task and result data is encrypted in transit.

## Autocompletion

Each framework and operations command has a autocompletion menu. Use the Tab Key to trigger suggestions, complete words, saving time and reducing errors by predicting what you're trying to enter.