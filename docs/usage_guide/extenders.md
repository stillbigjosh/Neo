# CLI Extender for Neo C2 Framework

The CLI Extender automatically registers Object files and Assemblies as remote client commands, allowing operators to run simplified commands that gets handled by their appropriate command chain. As such, Operators gets to extend the remote client based on their third-party tools. 


## Overview

The CLI Extender enables operators to run commands like `whoami` which automatically gets handled as `execute-bof cli/extensions/bof/whoami.x64.o` in the backend and sent to the remote client server.

## Features

- **Automatic Registration**: Automatically scans `cli/extensions/bof/`, `cli/extensions/assemblies/` and `cli/extensions/pe` directories for object files, assemblies and pe
- **Command Conversion**: Converts simple commands to its appropriate command chain (BOF, Assembly or PE)
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
Extension Commands Help:
  extender list          - Show all available extension commands
  extender info <name>   - Show detailed information about a specific extension
  extensions             - Alternative command for 'extender list'
```

### List All Extensions
```
NeoC2 (user@remote) > extender list
Available Extension Commands:
--------------------------------------------------------------------------------
Command              Type       File                      Description
--------------------------------------------------------------------------------
whoami               bof        whoami.x64.o              Display the current user context
--------------------------------------------------------------------------------
Total: 1 extension commands
```

### Show Extension Information
```
NeoC2 (user@remote) > extender info whoami

Extension Information
==================================================
Command:     whoami
Type:        BOF
Name:        whoami
Version:     0.0.0
Author:      @Trustedsec
Repository:  https://github.com/trustedsec/CS-Situational-Awareness-BOF
Help:        Display the current user context
Usage:       whoami
==================================================
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

### Portable Executables
- Located in: `cli/extensions/pe/`
- File pattern: `*.exe`, `*.dll`
- Converted to: `execute-pe <file_path> [arguments]`


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

N.B: _Extensions of the same name and type in the same sub-folder would cause conflict during name extraction, e.g `whoami.x64.o` & `whoami.x86.o`. This will result in one of the two getting executed everytime `whoami` is run. Extensions that fall into this catgory can be run directly using its corresponding module `execute-bof whoami.x86.o`_ 

## JSON Metadata Support

Extensions can include optional JSON metadata files that provide detailed information about the extension. The JSON file should have the same base name as the extension file.

### JSON File Location
- `cli/extensions/bof/whoami.json` for `whoami.x64.o`
- `cli/extensions/assemblies/mimikatz.json` for `mimikatz.exe`
- `cli/extensions/pe/procdump.json` for `procdump.exe`

### JSON File Format
```json
{
  "name": "whoami",
  "version": "0.0.0",
  "extension_author": "Neo C2 Framework",
  "original_author": "@Trustedsec",
  "repo_url": "https://github.com/trustedsec/CS-Situational-Awareness-BOF",
  "help": "Display the current user context",
  "usage": "whoami"
}
```

### Metadata Fields
- `name`: The name of the extension
- `version`: Version of the extension
- `extension_author`: Author of the extension wrapper
- `original_author`: Original author of the tool
- `repo_url`: Repository URL for the extension
- `help`: Brief description of what the extension does
- `usage`: Usage information for the extension

### Optional Metadata
The JSON metadata files are completely optional. Extensions without JSON files will still work normally, but will show "N/A" for metadata fields when using `extender info <name>`.

## Integration

The extender integrates seamlessly with the existing Neo C2 CLI:
- Tab completion includes extension commands
- Works in both regular and interactive modes
- Maintains compatibility with all existing commands
- Provides clear conversion messages when commands are converted
