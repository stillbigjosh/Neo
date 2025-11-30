# The NeoC2 Framework

_A modular server-client architecture post-exploitation framework built for collaborative agent management in red team operations and security testing. Enables flexibility by allowing operators to add their own modules._

<p align="center"><img width="250" height="250" alt="neoc2" src="https://github.com/user-attachments/assets/6da0f8c9-2e12-49cf-8111-63b401431dac" /></p>

### Architecture
- Flask based web application handles all agent's HTTP/S communications
- Profile-driven Configuration: Malleable profiles for customizing agent behavior and communication patterns
- Modular Design: Add your own Extensible modules for post-exploitation tasks via Python wrappers
- Polymorphic Payloads: Generate unique, obfuscated payloads for evasion
- SQLite-based storage for persistent data storage

### Managers
- The Agent Manager: Core component coordinating communication between agents and other framework components.
- Modules manager: Manages post-exploitation modules and commands. Operators can also build/bring own modules and plug it in to the c2.
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

### Prerequisites
- Linux Machine
- Python 3.*
- Golang
- Virtual environment (recommended)
- OpenSSL for HTTPS certificates

### Environment Variables
**Using .env file for service (production/service)**
- Environment variables are read from the `.env` file located at `/opt/neoc2/.env`
- For service deployments, credentials should be set in `/opt/neoc2/.env`
**Common Environment Variables:**
```bash
...
IP=<your public ip>
SECRET_KEY=<your random key>      # Change from default
DEFAULT_USERNAME=<your username>  # REQUIRED - no default provided
DEFAULT_PASSWORD=<your pass>      # REQUIRED - no default provided
```
NOTE: 
- THE CREDENTIALS SET VIA THE ENVIRONMENT VARIABLE IS THE INITIAL/DEFAULT ADMINISTRATOR. 
- AFTER STARTING THE FRAMEWORK, NAVIGATE TO https://<ip>:7443 (THE USER MANAGEMENT PORTAL) 
- GIVE THIS REGISTRATION LINK TO OTHER MULTIPLAYERS.
- REGISTERED OPERATORS CAN BE APPROVED AND ASSIGNED A ROLE VIA THE ADMINISTRATIVE USER MANAGEMENT INTERFACE.

### Service Installation (Recommended for permanent deployment)
To run NeoC2 as a background service that starts automatically on boot:
1. **Install prerequisites and setup**
   ```bash
   ./install.sh
   ```
2. **Configure your environment variables** in `.env` file 
3. **Install and start the service**
   ```bash
   sudo ./setup_service.sh
   ```
4. **Verify service installation**
   ```bash
   neoc2 status
   ```

### Service Management
```bash
# Global command
neoc2
# Start the service
neoc2 start
# Stop the service
neoc2 stop
# Restart the service
neoc2 restart
# View service logs
neoc2 logs
```

### Start CLI 
Default user set via environment variable is Administrator. Other multiplayer operators can login via register via the web and have an Administrator approve and assign a role.
```bash
neoc2-cli --server <IP>:8444 --username <> --password <>
```

### Basic Workflow
Building a payload using the listener created from your profile config ensures that your chosen API endpoints are visible to the Endpoint Auto-detection Background service.

1. Using default listener and profile

```
NeoC2 > listener start web_app_default
# Build payload
NeoC2 > payload list
NeoC2 > payload <agent_type> <listener_name>
# List active agents
NeoC2 > agent list
# Interact with agent
NeoC2 > interact <agent-id>
```

2. Using custom profile and own listener
```
# Add communication profile 
# Sample communication profile in profiles/sample.json
# Change its endpoints based on your intended usage
NeoC2 > profile add profiles/profile.json
NeoC2 > profile list

# Create a HTTPS listener
NeoC2 > listener create <listener_name> https <port> <IP> profile_name=<profile_name>
NeoC2 > listener start <listener_name>

# Build payload 
NeoC2 > payload <agent_type> <listener_name>
```
USE `neoc2 logs` TO MONITOR NEW AGENT REGISTERS ON A SEPARATE TERMINAL


```
# List active agents
NeoC2 > beacon
NeoC2 > agent list
# Interact with agent
NeoC2 > interact <agent-id>
```

### Default Ports
- Default HTTP/HTTPS Listener: 443
- User management: 7443
- Remote CLI: 8444

## Documentation 
Please [https://neoc2.readthedocs.io/en/latest/](https://neoc2.readthedocs.io/en/latest/) for Usage guides 

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
