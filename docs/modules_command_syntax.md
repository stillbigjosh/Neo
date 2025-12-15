# NeoC2 Module Command Syntax

- [General Syntax](#general-syntax)
- [Examples](#examples)

## General Syntax

```
run <module_name> <agent_id> <option>=<value>

# In interactive mode, the agent ID is automatically inferred:
run <module_name> <option>=<value>
```

The module example given here is a placeholder, intended to help the operator understand how to run their extensible modules. 

Read [modules.md](#docs/modules.md) for a guide on the modularity of the framework.

Run `modules list` for a list of both external and built-in modules that might and might not be covered by this guide and pull their usage info with `modules info <name>`

## Example:

### Get-ComputerDetail Module

The `Get-ComputerDetail` (external module with a Python-wrapper) executes a PowerShell script to gather comprehensive system information including OS details, hardware specs, network configuration, and running processes.

#### Required Options:
- `agent_id`: ID of the agent to run Get-ComputerDetail on

#### Optional Options:
- `computer_name`: Target computer name or IP address to enumerate (default: localhost)
- `credentialed_access`: Use alternate credentials for remote enumeration (format: domain\\username:password)
- `property`: Specific property to retrieve (optional, if not specified, all properties will be returned)

#### Examples:

**Basic Computer Detail Enumeration:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Remote Computer Detail Enumeration:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10
```

**Computer Detail with Specific Property:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 property=OSInfo
```

**Computer Detail with Credentials:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 credentialed_access=DOMAIN\\admin:password123 property=HardwareInfo
```


## Notes

- The `agent_id` parameter is IMPORTANT in non-interactive mode as it specifies which agent should execute the module. 
- For cross-platform modules, ensure the appropriate method/technique is selected for the target OS
- Some techniques require specific privileges or services to be running on target systems
- Credentials should be formatted properly as shown in the examples

