# The NeoC2 Framework 
<a href="https://github.com/stillbigjosh/Neo"><img alt="Release" src="https://img.shields.io/badge/release-1.4.1-blue.svg"/></a> <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/License-GPL-green.svg"/></a> <a href=""><img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey.svg"/></a> 

_A modular server-client architecture post-exploitation framework built for collaborative agent management in red team operations and security testing. Enables flexibility by allowing operators to add their own modules._

### Architecture
- Teamserver: Integrates the various managers of the command-and-control
- Flask based web application handles all agent's HTTP/S communication endpoints
- Listener stack: Runs as a separate processes from the Flask application, acting as internal redirectors, forwards traffic from agents to the web application
- Remote Client: Separate from the C2 Server and can be operated from anywhere. CLI allows operators to connect to the C2 via the Multiplayer co-ordinator
- Polymorphic Payloads: These are unique, obfuscated implants with Anti-sandbox & Anti-debugger capability
- Malleable profiles: For customizing agent behavior and communication patterns
- Extensible modules: For post-exploitation tasks. External custom module are made operationally available via a Python-wrapper
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

### Miscellaneous Features
- In-memory BOF execution
- Execute .NET assemblies in-process 
- Execute arbitrary Windows executables (PE) in a sacrificial process
- Shellcode injection into sacrificial processes
- C2 Redirector support
- Multi-server failover deloyment support

## Installation:
NeoC2 works well on Kali Linux. See the [Installations](https://neoc2.readthedocs.io/en/latest/Installation/) docs for instructions. 

## Documentation 
Read [https://neoc2.readthedocs.io/en/latest/](https://neoc2.readthedocs.io/en/latest/) for all Usage guides 

Blog PART 1: Learning: Neo Command & Control Framework (Part 1) Tutorial & Usage guide [https://medium.com/@stillbigjosh/learning-neo-command-control-framework-part-1-912ac0b68f2b](https://medium.com/@stillbigjosh/learning-neo-command-control-framework-part-1-912ac0b68f2b)

Blog PART 2: Learning: Neo Command & Control Framework (Part 2) Tutorial & Usage guide [https://stillbigjosh.medium.com/learning-neo-command-control-framework-part-2-tutorial-usage-guide-f2891b44a96d](https://stillbigjosh.medium.com/learning-neo-command-control-framework-part-2-tutorial-usage-guide-f2891b44a96d)

Blog PART 3: Bypassing Windows 11 Defender with NeoC2 & MSFVenom [https://stillbigjosh.medium.com/bypass-windows-11-defender-with-neoc2-msfvenom-part-3-e61cbe055bde](https://stillbigjosh.medium.com/bypass-windows-11-defender-with-neoc2-msfvenom-part-3-e61cbe055bde)


### Contributions
This project is accepting contributions and under active development. You can submit a pull request or Join discussions https://github.com/stillbigjosh/Neo/discussions

### Disclaimer
Users are responsible for ensuring their use of this framework complies with laws, regulations, and corporate policies. The author cannot be held responsible for any malicious utilizations. The Software is intended exclusively for authorised penetration testers and security researchers who have obtained authorisation from the owner of each target system.
By downloading this software you are accepting the terms of use and the licensing agreement.

### Acknowledgments, Contributors & Involuntary Contributors
- [@TrustedSec](https://github.com/trustedsec/COFFLoader) For their awesome COFFLoader and BOF collections
- [@Praetorian](https://github.com/praetorian-inc) For making BOF loading functionality possible within the Go ecosystem
- [@PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit) For their repository of powershell modules to practice the extendibility of the C2

### Support
- **Bug Reports**: [Open an Issue](https://github.com/stillbigjosh/Neo/issues)
- **Feature Requests**: [Discussions](https://github.com/stillbigjosh/Neo/discussions)
- **Security Issues**: Contact @stillbigjosh privately 
  
_This Project is created and maintained by_ [@stillbigjosh](https://github.com/stillbigjosh)    
