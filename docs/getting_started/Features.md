
# Features

### Architecture
- Teamserver: The central command-and-control server housing various handlers and managers for the command-and-control operations. Contains the Agent Manager, Module Manager, Listener Manager, and other core components that coordinate C2 operations.
- Flask web application stack: Handles all agent HTTP/S communication endpoints through a RESTful API. Serves as the primary web interface for agent communication and operator dashboards.
- Listener stack: Runs as separate processes from the Flask application, acting as internal redirectors. Supports multiple protocols (HTTP/S, TCP) and forwards traffic from agents to the web application. Each listener operates independently with its own process space for enhanced stability and security.
- Remote Client: Separate from the C2 Server and can be operated from anywhere. CLI allows operators to connect to the C2 via the Multiplayer coordinator. Provides secure remote access to all C2 capabilities.
- Modular Payload Design: Customize the payload capability by including or excluding specific advanced features. Payloads can be generated with different capabilities (BOF execution, assembly loading, PE execution, etc.) based on operational needs.
- Polymorphic Payloads: These are modular, unique, obfuscated implants with Anti-sandbox & Anti-debugger capability. Payloads are dynamically generated with obfuscation techniques to evade detection.
- Malleable profiles: For customizing agent behavior and communication patterns (working hours, kill-date, heartbeat intervals, jitter, endpoint patterns, etc.). Profiles define how agents communicate with the C2 and what behaviors they exhibit.
- Multi-Operator Extension Module System: Operators use their own local extension modules without interfering with each other. Each operator can load custom modules locally without affecting other operators.
- SQLite-based storage for persistent data storage: All framework data (agents, tasks, results, users, listeners, modules) is stored in a SQLite database for reliability and portability.
- High-Performance Web Stack: The command-and-control utilizes Gunicorn with gevent workers to provide asynchronous, high-concurrency handling of agent communications. This architecture enables stable operation under real-world traffic loads with thousands of concurrent agent connections while maintaining low latency for interactive operations.

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
- Execute arbitrary Windows executables (PE) in agent memory apace
- Shellcode injection into sacrificial processes with NtQueueApcThread, NtCreateThreadEx, RtlCreateUserThread, CreateRemoteThread
- C2 redirectors support
- Multi-server failover deployment support
- Seamless Payload staging with custom endpoints



