# CLI Extender for Neo C2 Framework

The CLI Extender automatically registers object files as remote client commands, allowing operators to run simplified commands that get converted to the appropriate execute commands.

## Overview

The CLI Extender enables operators to run commands like `whoami` which automatically get converted to `execute-bof cli/extensions/bof/whoami.x64.o` in the backend and sent to the remote client server.

## Features

- **Automatic Registration**: Automatically scans `cli/extensions/bof/` and `cli/extensions/assemblies/` directories for object files
- **Command Conversion**: Converts simple commands to appropriate execute commands (BOF or Assembly)
- **Argument Support**: Supports passing arguments to extension commands
- **Tab Completion**: Integrates with CLI tab completion for extension commands
- **Full Command Compatibility**: Operators can still run full commands like `execute-bof whoami.x64.o`
- **Architecture Handling**: Automatically extracts command names from files like `whoami.x64.o`, `mimikatz.x86.o`, etc.

## Usage

### Extension Commands
```
NeoC2 (user@remote) > whoami
[*] Converted extension command: 'whoami' -> 'execute-bof cli/extensions/bof/whoami.x64.o'
[+] Command sent to server...
```

### Extension Commands with Arguments
```
NeoC2 (user@remote) > whoami -u
[*] Converted extension command: 'whoami -u' -> 'execute-bof cli/extensions/bof/whoami.x64.o -u'
[+] Command sent to server...
```

### Full Commands (Still Supported)
```
NeoC2 (user@remote) > execute-bof cli/extensions/bof/whoami.x64.o
[+] Command sent to server...
```

### List Available Extensions
```
NeoC2 (user@remote) > extender
Available Extension Commands:
------------------------------------------------------------
Command              Type       File                     
------------------------------------------------------------
whoami               bof        whoami.x64.o             
------------------------------------------------------------
Total: 1 extension commands
```

## Supported File Types

### BOF Files
- Located in: `cli/extensions/bof/`
- File pattern: `*.o` (e.g., `whoami.x64.o`, `mimikatz.x86.o`)
- Converted to: `execute-bof <file_path> [arguments]`

### Assembly Files  
- Located in: `cli/extensions/assemblies/`
- File pattern: `*.exe`, `*.dll`
- Converted to: `execute-assembly <file_path> [arguments]`

## Command Name Extraction

The extender extracts command names from filenames by:
1. Removing architecture indicators (x64, x86, amd64, arm, arm64)
2. Removing file extensions (.exe, .dll, .o)
3. Validating the resulting command name

Examples:
- `whoami.x64.o` → `whoami`
- `mimikatz.x86.o` → `mimikatz`  
- `SharpHound.exe` → `SharpHound`
- `Seatbelt.dll` → `Seatbelt`

## Integration

The extender integrates seamlessly with the existing Neo C2 CLI:
- Tab completion includes extension commands
- Works in both regular and interactive modes
- Maintains compatibility with all existing commands
- Provides clear conversion messages when commands are converted