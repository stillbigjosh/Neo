# The NeoC2 Framework

_A modular server-client architecture post-exploitation framework built for collaborative agent management in red team operations and security testing. Enables flexibility by allowing operators to add their own modules._

<p align=center>
  <a href="https://github.com/stillbigjosh/Neo"><img alt="Release" src="https://img.shields.io/badge/Release-1.1.3-blue.svg"/></a>
</p>

<p align="center"><img width="250" height="250" alt="neoc2" src="https://github.com/user-attachments/assets/6da0f8c9-2e12-49cf-8111-63b401431dac" /></p>

### Architecture
- Flask based web application handles all agent's HTTP/S communications
- Profile-driven Configuration: Malleable profiles for customizing agent behavior and communication patterns
- Modular Design: Add your own Extensible modules for post-exploitation tasks via Python wrappers
- Polymorphic Payloads: Generate unique, obfuscated payloads for evasion
- SQLite-based storage for persistent data storage

### Managers
- The Agent Manager: Core component coordinating communication between agents and other framework components.
- Modules manager: Manages post-exploitation modules that can be executed on agents. 
- Role and User Manager: Co-ordinates role-based access control (RBAC) with admin/operator/viewer roles 
- Audit logger: Tracks user actions and permissions
- Multiplayer session management: allows multiple operators to work simultaneously
- Task Orchestrator: Chain modules for complex operations
- Remote CLI Server: manages remote command-line interface for synchronized agent management and interactive sessions

### Security Features
- Payloads are pre-registered with agent ID and embedded encryption key. C2 validates the secret key and enforces encrypted communication using Fernet AES-128-CBC
- Multiple authentication layers (sessions, tokens, roles)
- Input validation and command injection prevention
- Configurable HTTP/S endpoint URLs to evade detection

### Multiplayer Features
- Real-time collaboration between operators
- Agent presence tracking
- Interactive session locking
- User presence and status management

## Installation:
NeoC2 works well on Kali Linux. See the [Installations](https://neoc2.readthedocs.io/en/latest/Installation/) docs for instructions. 

## Documentation 
Read [https://neoc2.readthedocs.io/en/latest/](https://neoc2.readthedocs.io/en/latest/) for all Usage guides 

Blog PART 1: Learning: Neo Command & Control Framework (Part 1) Tutorial & Usage guide [https://medium.com/@stillbigjosh/learning-neo-command-control-framework-part-1-912ac0b68f2b](https://medium.com/@stillbigjosh/learning-neo-command-control-framework-part-1-912ac0b68f2b)

Blog PART 2: Learning: Neo Command & Control Framework (Part 2) Tutorial & Usage guide [https://stillbigjosh.medium.com/learning-neo-command-control-framework-part-2-tutorial-usage-guide-f2891b44a96d](https://stillbigjosh.medium.com/learning-neo-command-control-framework-part-2-tutorial-usage-guide-f2891b44a96d)


### Contributions
This project is accepting contributions and under active development. You can reach out to @stillbigjosh or Join discussions https://github.com/stillbigjosh/Neo/discussions

### Disclaimer
Users are responsible for ensuring their use of this framework complies with laws, regulations, and corporate policies. The author cannot be held responsible for any malicious utilizations. The Software is intended exclusively for authorised penetration testers and security researchers who have obtained authorisation from the owner of each target system.
By downloading this software you are accepting the terms of use and the licensing agreement.


### Acknowledgments, Contributors & Involuntary Contributors
- [@TrustedSec](https://github.com/trustedsec/COFFLoader) For their awesome COFFLoader and BOF collections 
- [@PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit) For their repository of powershell modules to practice the extendibility of the C2


_This Project is created and maintained by_ [@stillbigjosh](https://github.com/stillbigjosh)    
