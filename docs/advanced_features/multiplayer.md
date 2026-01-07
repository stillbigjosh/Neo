# Multiplayer System

NeoC2 supports multiplayer functionality that allows multiple users to collaborate simultaneously. The system provides real-time updates, and coordinated access to agents with role-based access control (RBAC) to ensure proper permissions.

## Features

### Interactive Locks
Exclusive access to agents when performing interactive operations:

```
# CLI: Interact with agent (acquires interactive lock)
agent interact <agent_id>

# Prevents other users from acquiring interactive lock on same agent
# Shows lock status in agent info
```

## Authentication and RBAC

The multiplayer system maintains the same RBAC structure as the base framework:

- **Admin**: Full access to all features
- **Operator**: Can manage agents and execute modules
- **Viewer**: Read-only access to agents and results

Authentication works through:
- Environment variables (`NEOC2_USERNAME`, `NEOC2_PASSWORD`)
- Registration and Admin role approval via the Web


### Example 1: Coordinated Agent Interaction
```
User A (CLI): agent interact abc123
# Acquires exclusive interactive lock
User B (Web): Tries to interact - receives message that User A has lock
User A (CLI): agent info abc123
# Shows User A has interactive access
```

## Remote CLI Access

### Remote CLI Server Configuration
The remote CLI server is enabled by default and can be configured through the main configuration file config.json created after C2 starts.

```json
{
  "remote_cli": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8444,
    "ssl_enabled": true,
    "cert_file": "server.crt",
    "key_file": "server.key"
  }
}
```

### Remote CLI Client Usage
Connect to the NeoC2 server using the remote CLI client:

```
# Basic connection
neoc2-cli --server <ip:port> --username <user> --password <pass>

# Connect without SSL (not recommended for production)
neoc2-cli --server <ip:port> --username <user> --password <pass> --no-ssl

# Example
neoc2-cli --server 192.168.1.100:8444 --username morpheus --password morpheus
```

### Port Information
When connecting via remote CLI, you must use the **Remote CLI Server Port**, which is different from other system ports:
- Default `8444` 

To connect, always use the Remote CLI Server Port (typically 8444):
```bash
# Connect to local instance
neoc2-cli --server 127.0.0.1:8444 --username morpheus --password morpheus

# Connect to remote server  
python cli/remote_cli.py --server 192.168.1.100:8444 --username morpheus --password morpheus
```

You can verify the correct port in your framework startup logs:
```
Remote CLI Server started successfully on 0.0.0.0:8444
```

Or check your `config.json` file under the `remote_cli` section for the configured port number.

### Troubleshooting Remote CLI
#### Connection Issues
```
Error: Connection error: [Errno 111] Connection refused
```
- Verify the remote CLI server is running on the specified host and port
- Check firewall rules allow connections to the remote CLI port (default 8444)
- Confirm SSL certificate files exist if using SSL

#### Authentication Failures
```
[-] Authentication error: Authentication failed
```
- Verify username and password are correct
- Confirm user exists and is active in the database
- Check user permissions and role assignment

#### Command Execution Errors
```
Error: Command execution error: ...
```
- Check server logs for detailed error information
- Verify the user has required permissions for the command
- Confirm the command syntax is correct

#### SSL/TLS Issues
```
Error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```
- Use `--no-ssl` flag for testing (not recommended for production)
- Ensure SSL certificate files are properly configured
- Verify certificate matches the server hostname

