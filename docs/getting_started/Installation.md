# Installation


- [How to install](#how-to-install)
- [Basic workflow](#basic-workflow) 


## How to install

#### Prerequisites:
- Linux (Debian)
- Python 3.1
- Golang 1.2
- Python virtual environment (python3-venv)
- OpenSSL/LetsEncrypt

```bash
sudo apt-get install golang
sudo apt-get install python3-venv
git clone https://github.com/stillbigjosh/Neo.git
nano .env
```

#### Environment Variables

**Using .env file for service installation:**

- Environment variables needed by the framework are read from the `.env` file in the root folder. The credentials in the file would be the default logins for adminsitrative user management and the remote client.

- The secret key is needed for payload staging and other XOR-based operations.

- Ensure you change the four lines below only:

```bash
...
IP=<ip4_address>
SECRET_KEY=<randomized_key>       # CHANGE from default
DEFAULT_USERNAME=<admin_username>  # REQUIRED - no default provided
DEFAULT_PASSWORD=<admin_password>      # REQUIRED - no default provided
```


#### Service Installation 

Neo command-and-control server is installed as a background service that starts automatically on boot:

1. **Configure your environment variables** in `.env` file

2. **Install and start the service**: 
   ```
   sudo setup/install.sh
   ```
This will install all dependencies in a python virtual environment. Generates an OpenSSL self-signed certificate. Installation path of the framework after running this will be `/opt/neoc2/` and would also creates two globally available commands for interacting with the C2 Server service instance `neoc2` and a launcher for the C2 Remote Client `neoc2-cli`

3. **Verify service installation**
   ```
   neoc2 status
   ```
   
4. Post-installation, ensure you change the `secret_key` and `internal_api_token` values in `/opt/neoc2/config.json` from the default and run `neoc2 restart`. This secret_key is used by Flask as a secret key for signing sessions and other security-related functions. It's required for Flask's session management and CSRF protection mechanisms. The internal_api_token adds a layer of protection against external access to sensitive profile configurations needed by the internal services.


#### Service Management
These two global commands: `neoc2` and `neoc2-cli` were made globally available after setup. The former for managing the Neo C2 Server running in background as a service, and the latter for remote-ing as a multiplayer client. 
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

#### Default Ports
- Default HTTP/HTTPS Listener: 443
- Flask Web Application and Administrative User Management components of the framework port: 7443 
- TeamServer's Remote Client Manager port: 8444
- Default Tty_shell port: 5000
- Default Server-Side Reverse Proxy: 5555
- Default SOCKS5 Proxy Chain: 1080

#### Start CLI 
Default user set via environment variable is Administrator. Other multiplayer operators can login via register via the web and have an Administrator approve and assign a role.
```bash
neoc2-cli --server <IP>:8444 --username <> --password <>
```

- AFTER STARTING THE FRAMEWORK, NAVIGATE TO https://$IP:7443 (THE USER MANAGEMENT PORTAL) 
- GIVE ITS REGISTRATION LINK TO OTHER MULTIPLAYERS.
- REGISTERED OPERATORS CAN BE APPROVED AND ASSIGNED A ROLE VIA THE ADMINISTRATIVE USER MANAGEMENT INTERFACE.

## Basic workflow
Building a payload using the listener created from your profile config ensures that your chosen API endpoints are visible to the Endpoint Auto-detection Background service.

- Using default listener and profile (In real engagement, use custom profile)
```
# Make any required change to the default profile in profiles/default.json
NeoC2 > profile reload profiles/default.json # OPTIONAL 
NeoC2 > listener start web_app_default
# Build payload
NeoC2 > payload list
NeoC2 > payload <agent_type> <listener_name>
# List active agents
NeoC2 > agent list
# Interact with agent
NeoC2 > interact <agent-id>
```

- Using custom profile and own listener
```
# Add communication profile 
# Sample communication profile in profiles/sample.json
# Change its endpoints based on your intended usage
NeoC2 > profile add profiles/profile.json

# Create a HTTPS listener
NeoC2 > listener create <listener_name> https <port> <IP> profile_name=<your_custom_profile_name>
NeoC2 > listener start <listener_name>

# Build payload 
NeoC2 > payload <agent_type> <listener_name>
```

#### Agent Register

The Neo C2 Server automatically alerts all connected clients when a deployed implant is active or registers: `[+] NEW AGENT: ID=c272-xxxx HOST=xxxx USER=root IP=127.0.0.1 OS=xxxx`

#### List active agents

```
NeoC2 > beacon
NeoC2 > agent list
```

#### Modes

The Neo C2 has two operation mode based on its [task management system](usage_guide/task_management.md): 

- Default queued mode: Tasks are stored in the database and retrieved by agents during their regular polling cycles

- Interactive mode: Tasks and Modules bypasses the standard queue and communicate directly with agents in real-time via the interactive API
```
interact <agent_id>
```




