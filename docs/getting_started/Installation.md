# Installation


- [How to install](#how-to-install)
- [Basic workflow](#basic-workflow) 


## How to install

#### Prerequisites
- Linux Machine
- Python 3.*
- Golang 1.*
- Python virtual environment (python3-venv)
- OpenSSL for HTTPS certificates

```bash
sudo apt-get install golang
sudo apt-get install python3-venv
git clone https://github.com/stillbigjosh/Neo.git
nano .env
```

#### Environment Variables
**Using .env file for service installation**
- Environment variables are read from the `.env` file 
```bash
...
IP=<your public ip>
SECRET_KEY=<your random key>      # CHANGE from default
DEFAULT_USERNAME=<your username>  # REQUIRED - no default provided
DEFAULT_PASSWORD=<your pass>      # REQUIRED - no default provided
```

- THE CREDENTIALS SET VIA THE ENVIRONMENT VARIABLE IS THE INITIAL/DEFAULT ADMINISTRATOR. 

#### Service Installation 

Neo command-and-control server is installed as a background service that starts automatically on boot:

1. **Configure your environment variables** in `.env` file

2. **Install and start the service**: This will install all dependencies in a python virtual environment. Generates an OpenSSL self-signed certificate. Installation path of the framework after running this will be `/opt/neoc2/` and would also creates two globally available commands for interacting with the C2 Server service instance `neoc2` and a launcher for the C2 Remote Client `neoc2-cli`
   ```
   sudo ./install.sh
   ```

3. **Verify service installation**
   ```
   neoc2 status
   ```
   
4. Post-installation, ensure you change the secret_key and internal_api_token values in `/opt/neoc2/config.json` from the default and run `neoc2 restart`. The secret_key is used by Flask as a secret key for signing sessions and other security-related functions. It's required for Flask's session management and CSRF protection mechanisms. The internal_api_token adds a layer of protection against external access to sensitive profile configurations needed by the internal services.


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
- The Flask Web Application and Administrative User Management components of the framework runs on Port 7443 
- The TeamServer's Remote CLI Manager is exposed on Port 8444

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
NeoC2 > listener create <listener_name> https <port> <IP> profile_name=my_https_profile
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



--

