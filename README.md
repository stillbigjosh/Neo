<div align="center">

<img src="docs/assets/img.jpeg" alt="Logo" width="220" style="margin-bottom: 20px;"/>

# The Neo C2 Framework 

[![Version](https://img.shields.io/badge/Version-2.0.1-orange.svg)](https://github.com/stillbigjosh/Neo/releases)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Golang](https://img.shields.io/badge/Go-1.2%2B-blue.svg)](https://www.go.dev/)
[![License](https://img.shields.io/badge/License-GPL-green.svg)](LICENSE)
[![Tool](https://img.shields.io/badge/Tool-Adversary%20Emulation-red.svg)](https://github.com/stillbigjosh/Neo)
[![Platform](https://img.shields.io/badge/platform-Linux%20Windows%20MacOS-lightgrey.svg)](https://github.com/stillbigjosh/Neo)



**A modular server-client architecture post-exploitation framework built for collaborative agent management in red team operations and security testing. Enables flexibility by allowing operators to add their own extension modules**

[Installation](https://neoc2.readthedocs.io/en/latest/getting_started/Installation/) • [Agents & Stagers](https://neoc2.readthedocs.io/en/latest/core_concepts/agents_and_stagers_guide/) • [Profiles & Listeners](https://neoc2.readthedocs.io/en/latest/usage_guide/profiles_and_listeners/) • [Modules](https://neoc2.readthedocs.io/en/latest/usage_guide/specialized_modules/) • [Multiplayer](https://neoc2.readthedocs.io/en/latest/advanced_features/multiplayer/) • [SOCKS5](https://neoc2.readthedocs.io/en/latest/usage_guide/socks5_pivot/) • [Task Orchestration](https://neoc2.readthedocs.io/en/latest/advanced_features/taskorchestration/)

</div>



---

### Features
- **Scalability:** The server uses production-level WSGI gunicorn with gevent for stability and performance under real-world traffic, unlike Flask development servers
- **Multiplayer-mode:** Real-time collaboration between operators with Interactive session locking
- **Proxy Awareness:** SOCKS5 reverse proxy functionality
- **Task Orchestrator**: Chain modules for complex operations
- **Role-Based Access Control:** Co-ordinates access and permissions with admin/operator/viewer roles
- **Multi-Operator Extension Module System:** Operators integrate their own local extension modules without interfering with each other
- **Modular Payload Architecture** Customize the implant capability by including or excluding specific advanced features
- **Polymorphic Payloads:** Randomized variable and function names, XOR-based string obfuscation
- **Secure Communication:** HTTPS is the primary C2 channel. Implants are pre-registered with a per-agent symmetric keys (AES-128-CBC + HMAC-SHA256). The framework validates the secret key and enforces encrypted communication using Fernet layer over HTTPS
- **Malleable profiles:** Customize agent behavior and communication patterns
- **Sanbox & Debugger Detection**: Anti-analysis self-deletion 
- **Payload staging** Seamless staging of payloads, files
- **Redirector Support**: Manage external infrastructure pointing to internal listeners via profiles
- **Failover deployment**: Agent embeds failover C2 servers
- **Shellcode Injection**: Shellcode injection into sacrificial processes with NtQueueApcThread, NtCreateThreadEx, RtlCreateUserThread, CreateRemoteThread
- **Unmanaged PE Execution**: Execute arbitrary Windows executables (PE) in a sacrificial process with Process Hollowing, or Complete PE execution in agent's memory space
- **.NET Assembly Execution**: In-memory execution of .NET Assemblies
- **BOF Execution**: Load and Execute Beacon Object Files 


### Installation
NeoC2 server and remote client are currently meant to be run on Kali Linux machines. See the [Installations](https://neoc2.readthedocs.io/en/latest/getting_started/Installation/) guide for instructions. 

### Documentation 
Read [https://neoc2.readthedocs.io/en/latest/](https://neoc2.readthedocs.io/en/latest/) for all Usage guides 

### Disclaimer
Users are responsible for ensuring their use of this framework complies with laws, regulations, and corporate policies. The author cannot be held responsible for any malicious utilizations. The Software is intended exclusively for authorised penetration testers and security researchers who have obtained authorisation from the owner of each target system.
By downloading this software you are accepting the terms of use and the licensing agreement.

### Acknowledgments, Contributors & Involuntary Contributors
- [@TrustedSec](https://github.com/trustedsec/COFFLoader) Awesome BOF collections
- [@Praetorian](https://github.com/praetorian-inc) COFFloader implementation for Go-ecosystem
- [@ropnop](https://github.com/ropnop) CLR library made executing .NET from Go
- [Sliver](https://github.com/BishopFox/sliver) This project was deeply inspired by Sliver
- [Mythic](https://github.com/its-a-feature/Mythic) Trinity Agent Modular build was inspired by Mythic

### Support
- **Bug Reports**: [Open an Issue](https://github.com/stillbigjosh/Neo/issues)
- **Feature Requests**: [Discussions](https://github.com/stillbigjosh/Neo/discussions)
- **Security Issues**: Contact @stillbigjosh privately 
  
_This Project is created and maintained by_ [@stillbigjosh](https://github.com/stillbigjosh)    
