# NeoC2 Task Orchestration System

## Overview
NeoC2 Task Orchestration system allows operators to create and execute automated sequences of modules across agents. This feature enables multi-step operations to be executed as a single command, improving efficiency and reducing the manual overhead of executing sequences of related modules.

Task chains are useful for:
- Automated reconnaissance campaigns (enum → scan → harvest)
- Privilege escalation chains (get_system → whoami → pslist)
- Post-exploitation sequences (keylog → screen_capture → exfil)
- Complex attack scenarios that require multiple modules to be executed in sequence

## Command Structure

All task orchestration commands follow the format: `taskchain <action> [options]`

## Available Commands

### 1. Create Task Chain

Creates a new task chain with specified modules and options.

```
taskchain create <agent_id> <module1=arg1,arg2,module2=arg3,module3> [name=chain_name] [execute=true]
```

**Parameters:**
- `agent_id`: The target agent ID to execute the chain on
- `<module1=arg1,arg2,module2=arg3,module3>`: Enhanced format with module-specific arguments
- `name=chain_name`: (Optional) Name for the task chain
- `execute=true`: (Optional) Execute the chain immediately after creation (default: false)

**Syntax:**
The syntax allows specifying arguments for each module directly in the command:
- `module_name=arg1,arg2` executes the same module multiple times with different arguments
- `module1=arg1,module2=arg2` executes different modules with their respective arguments
- Arguments containing commas, parentheses, or quotes are properly handled within the syntax
- You can mix module types (with and without arguments) in the same command

**Enhanced Syntax Features:**
- **Multi-argument module execution**: Execute the same module with multiple different arguments in sequence
- **Module-specific arguments**: Pass specific file paths, scripts, or parameters to each module type
- **Intelligent comma handling**: Commas within parentheses, brackets, or quotes are preserved correctly
- **Full module compatibility**: Works with all NeoC2 modules including execute-bof, pwsh, execute-assembly, and custom modules

**Examples:**
```bash
# Enhanced format - Execute multiple BOF files with execute-bof module
taskchain create AGENT001 execute-bof=whoami.x64.o,tasklist.x64.o,pwsh=Get-ComputerName.ps1,execute-assembly=rubeus.exe name=test

# Enhanced format with PowerShell and assembly execution
taskchain create AGENT001 pwsh=Invoke-Mimikatz.ps1,execute-assembly=SharpHound.exe name=test

# Create and immediately execute a chain using enhanced syntax
taskchain create AGENT001 peinject=netview.exe,execute-assembly=Seatbelt.exe execute=true

# Mixed format - combining modules with and without arguments
taskchain create AGENT001 execute-bof=whoami.o,get_system,whoami,execute-assembly=rubeus.exe name=mixed_chain

```

### 2. List Task Chains

Lists all task chains or filters by specific criteria.

```
taskchain list [agent_id=<agent_id>] [status=<status>] [limit=<limit>]
```

**Parameters:**
- `agent_id=<agent_id>`: (Optional) Filter chains by specific agent ID
- `status=<status>`: (Optional) Filter by status (pending, running, completed, failed)
- `limit=<limit>`: (Optional) Limit number of results (max 100, default 50)

**Examples:**
```bash
# List all task chains
taskchain list

# List chains for specific agent
taskchain list agent_id=AGENT001

# List pending chains for specific agent
taskchain list agent_id=AGENT001 status=pending

# List with limit
taskchain list limit=25
```

### 3. Check Chain Status

Displays detailed status information for a specific task chain.

```
taskchain status <chain_id>
```

**Parameters:**
- `chain_id`: The unique identifier of the task chain to check

**Example:**
```bash
# Check status of a specific chain
taskchain status CHAIN1234567890
```

**Output includes:**
- Chain ID and name
- Target agent ID
- Chain status (pending, running, completed, failed)
- Creation, start, and completion timestamps
- Individual task status and results
- Error information if tasks failed

### 4. Execute Chain

Manually starts execution of a previously created chain.

```
taskchain execute <chain_id>
```

**Parameters:**
- `chain_id`: The unique identifier of the task chain to execute

**Example:**
```bash
# Execute a specific chain
taskchain execute CHAIN1234567890
```

### 5. Help

Displays usage information and examples.

```
taskchain help
```

## Chain Execution Flow

When a task chain is executed, it follows this execution flow:

1. **Validation Phase**:
   - Verify agent exists and is online
   - Check agent is not locked by another operator
   - Validate all modules in the chain exist
   - Ensure all required module parameters are provided

2. **Execution Phase**:
   - Execute modules in sequence (1 → 2 → 3 → ...)
   - Wait for each task to complete before starting the next
   - If any task fails, the chain execution stops
   - Store results and status for each task

3. **Status Tracking**:
   - Each task has its own status (pending, running, completed, failed, cancelled)
   - Chain status reflects the overall progress
   - Error details are preserved for troubleshooting

## Module Compatibility

Task chains work with any NeoC2 module that follows the standard module interface. Common use cases:

### Reconnaissance Chains
```bash
# Basic enumeration
taskchain create AGENT001 sysinfo,whoami,env_enum name=host_recon

# Network enumeration
taskchain create AGENT001 net_scan,port_scan,service_enum name=network_recon
```

### Post-Exploitation Chains
```bash
# Privilege escalation attempt
taskchain create AGENT001 get_system,whoami,pslist name=priv_escalation

# Data collection
taskchain create AGENT001 keylog,screen_capture,file_search name=data_harvest
```

### Cleanup Chains
```bash
# Activity cleanup
taskchain create AGENT001 clear_logs,kill_processes,cleanup_files name=cleanup
```

### Monitoring
- Monitor chain status regularly during execution
- Check individual task results if the chain fails
- Use the `taskchain status` command to track progress

## Troubleshooting

### Chain Not Starting
- Verify the agent is online and responsive
- Check that you have permissions to execute modules on the target agent `agent info <agent_id`
- Confirm all modules in the chain exist and are properly loaded

### Individual Task Failing
- Check the detailed status output for error messages
- Verify module-specific parameters and requirements
- Test the failing module individually before including it in a chain

### Chain Stuck in Running State
- Check agent connectivity and responsiveness
- Verify the agent's task queue for stuck tasks
- Consider restarting the agent if tasks appear to be hung

## Performance Considerations

- Longer chains may take considerable time to complete
- Consider the impact on agent resources when designing chains
- Limit the number of resource-intensive modules in a single chain
- Monitor agent performance during chain execution

## Example Workflows

### 1. Automated Penetration Test
```bash
# Create an automated penetration test sequence (legacy format)
taskchain create AGENT001 sysinfo,whoami,priv_enum,get_system,whoami,pslist name=auto_pen_test execute=true

# Enhanced format for more complex operations
taskchain create AGENT001 execute-bof=whoami.o,priv_enum.o,get_system,whoami,pslist name=enhanced_pen_test execute=true
```

### 2. Beacon Object File Execution (BOFs)
```bash
# Execute multiple BOF files in sequence
taskchain create AGENT001 execute-bof=whoami.x64.o,tasklist.x64.o,seatbelt.x64.o,pwsh=Get-ComputerName.ps1,execute-assembly=rubeus.exe name=bof_chain

# Multi-step enumeration with BOFs
taskchain create AGENT001 execute-bof=netview.x64.o,netsession.x64.o,execute-assembly=SharpHound.exe name=enum_chain
```

### 3. Incident Response
```bash
# Quick incident response data collection
taskchain create AGENT001 processes,network_connections,log_analysis,file_hashes name=incident_response
taskchain execute CHAIN1234567890

# Enhanced incident response with file collection
taskchain create AGENT001 execute-bof=netstat.o,pslist.o,pwsh=Get-EventLogs.ps1,execute-assembly=Seatbelt.exe name=enhanced_incident_response
```

### 4. Persistent Monitoring
```bash
# Regular monitoring chain
taskchain create AGENT001 sysinfo,service_check,process_monitor name=persistent_monitoring

# Enhanced monitoring with multiple checks
taskchain create AGENT001 execute-bof=service_enum.o,process_check.o,execute-assembly=SharpHound.exe name=enhanced_monitoring
```

### 5. Post-Exploitation
```bash
# Credential harvesting chain
taskchain create AGENT001 execute-bof=lsadump.o,secretsdump.o,execute-assembly=Rubeus.exe,pwsh=Invoke-Mimikatz.ps1 name=credential_harvest

# Lateral movement preparation
taskchain create AGENT001 execute-bof=netview.o,shares.o,execute-assembly=SharpHound.exe name=lateral_movement_prep
```
