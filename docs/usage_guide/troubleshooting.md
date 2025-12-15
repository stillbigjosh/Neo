# Troubleshooting

## Common Issues and Solutions

#### Agent Doesn't Register
- Check C2 server is running
- Verify firewall allows connections
- Check agent can reach server: `curl https://your-server:443/health`

#### Interactive Mode Times Out
- Increase timeout in `send_interactive_command`
- Check agent is still running
- Verify agent is polling (check agent output)

#### Commands Not Executing
- Check agent logs for errors
- Verify agent has permissions to execute command
- Try simple command first: `whoami`

#### Agent Shows as Inactive
- Check agent is still running
- Verify network connectivity
- Agent becomes inactive after 5 minutes of no check-ins

## Debugging Endpoints

```
curl ip:7443/health
```

## Useful CLI Commands for Troubleshooting

```
status                        # Show framework status
result list                   # Check for task results
agent list                    # Verify agent status
```