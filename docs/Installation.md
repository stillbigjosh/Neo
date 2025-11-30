# Installation


[How to install](#how-to-install)
[Basic workflow](#basic-workflow)


## How to install

### Prerequisites
- Linux Machine
- Python 3.*
- Golang 1.*
- OpenSSL for HTTPS certificates

### Environment Variables
**Using .env file for service (production/service)**
- Environment variables are read from the `.env` file located at `/opt/neoc2/.env`
- For service deployments, credentials should be set in `/opt/neoc2/.env`
**Common Environment Variables:**
```bash
...
IP=<your public ip>
SECRET_KEY=<your random key>
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
   ```
   ./install.sh
   ```
2. **Configure your environment variables** in `.env` file 
3. **Install and start the service**
   ```
   sudo ./setup_service.sh
   ```
4. **Verify service installation**
   ```
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

### Default Ports
- Default HTTP/HTTPS Listener: 443
- User management: 7443
- Remote CLI: 8444

### Start CLI 
Default user set via environment variable is Administrator. Other multiplayer operators can login via register via the web and have an Administrator approve and assign a role.
```bash
neoc2-cli --server <IP>:8444 --username <> --password <>
```

## Basic workflow
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

# Create a HTTPS listener
NeoC2 > listener create <listener_name> https <port> <IP> profile_name=profile.json
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


