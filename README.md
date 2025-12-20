# The NeoC2 Framework 
<a href="https://github.com/stillbigjosh/Neo"><img alt="Release" src="https://img.shields.io/badge/release-1.4.5-blue.svg"/></a> <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/License-GPL-green.svg"/></a> <a href=""><img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey.svg"/></a> 

_A modular server-client architecture post-exploitation framework built for collaborative agent management in red team operations and security testing. Enables flexibility by allowing operators to add their own modules._

### Features
- **Multiplayer-mode:** Real-time collaboration between operators with Interactive session locking
- **Task Orchestrator**: Chain modules for complex operations
- **Role-Based Access Control:** Co-ordinates access and permissions with admin/operator/viewer roles 
- **Polymorphic Payloads:** Randomized variable and function names, XOR-based string obfuscation
- **Malleable profiles:** Customize agent behavior and communication patterns
- **Sanbox & Debugger Detection**: Anti-analysis self-deletion 
- **Payload staging** Seamless staging of payloads, files
- **File Operations**: Upload and download files
- **Redirector Support**: Manage external infrastructure pointing to internal listeners via profiles
- **Failover deployment**: Agent embeds failover C2 servers
- **Fernet layer over HTTPS:** Per-agent symmetric keys (AES-128-CBC + HMAC-SHA256) Secure comms over HTTPS
- **Multi-Operator Extension Module System:** Operators use their own local extension modules without interfering with each other
- **Shellcode Injection**: Shellcode injection into sacrificial processes with CreateRemoteThread
- **Process Hollowing**: Unmanaged Portable Executables injection into sacrificial processes
- **.NET Assembly Execution**: In-memory execution of .NET Assemblies
- **BOF Execution**: Load and Execute Beacon Object Files 
- **Reporting handler:** Easy post-operation report writing


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
- [@TrustedSec](https://github.com/trustedsec/COFFLoader) Awesome BOF collections
- [@Praetorian](https://github.com/praetorian-inc) COFFloader implementation for Go-ecosystem
- [@ropnop](https://github.com/ropnop) CLR library made executing .NET from Go 

### Support
- **Bug Reports**: [Open an Issue](https://github.com/stillbigjosh/Neo/issues)
- **Feature Requests**: [Discussions](https://github.com/stillbigjosh/Neo/discussions)
- **Security Issues**: Contact @stillbigjosh privately 
  
_This Project is created and maintained by_ [@stillbigjosh](https://github.com/stillbigjosh)    
