
# Features

### Architecture
- Teamserver: The remote client server and the various managers of the command-and-control
- Flask based web application handles all agent's HTTP/S communication endpoints
- Listener stack: Runs as a separate processes from the Flask application, acting as internal redirectors, forwards traffic from agents to the web application
- Remote Client: Separate from the C2 Server and can be operated from anywhere. CLI allows operators to connect to the C2 via the Multiplayer co-ordinator
- Modular Payload Design: Customize the payload capability by including or excluding specific advanced features
- Polymorphic Payloads: These are modular, unique, obfuscated implants with Anti-sandbox & Anti-debugger capability
- Malleable profiles: For customizing agent behavior and communication patterns (working hours, kill-date, etc)
- Multi-Operator Extension Module System: Operators use their own local extension modules without interfering with each other
- SQLite-based storage for persistent data storage

### Managers
- The Agent Manager: Core component coordinating communication between agents and other framework components.
- Modules manager: Manages post-exploitation modules that can be executed on agents. 
- Role and User Manager: Co-ordinates role-based access control (RBAC) with admin/operator/viewer roles 
- Audit logger: Tracks user actions and permissions
- Multiplayer session management: allows multiple operators to work simultaneously
- Task Orchestrator: Chain modules for complex operations
- Remote CLI Server: manages remote command-line interface for synchronized agent management and interactive sessions
- Reporting handler to make post-operation report writing easy 

### Security Features
- HTTPS is the primary C2 channel. 
- Implants are pre-registered with an ID and per-agent symmetric keys (AES-128-CBC + HMAC-SHA256). The framework validates the secret key and enforces encrypted communication using Fernet layer over HTTPS
- All tasking and results JSON bodies are Fernet-encrypted per agent
- Multiple authentication layers (sessions, tokens, roles)
- Input validation and command injection prevention
- Role-Based Access Control

### Multiplayer Features
- Real-time collaboration between operators
- Agent presence tracking
- Interactive session locking
- User presence and status management

### Advanced Features
- Socks5 Reverse Proxying support
- Load and Execute BOFs in-memory
- Load and Execute .NET assemblies in-memory
- Execute arbitrary Windows executables (PE) in a sacrificial process with Process Hollowing
- Shellcode injection into sacrificial processes with NtQueueApcThread, NtCreateThreadEx, RtlCreateUserThread, CreateRemoteThread
- C2 redirectors support
- Multi-server failover deployment support
- Seamless Payload staging 


