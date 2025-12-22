# Client Architecture

This directory contains the Client component of the command-and-control framework, separate from the Server and can be operated from anywhere. Allowing Multiplayers connect to NeoC2 Servers, provided you have the right permissions. 

## Components 
- **Remote Client**
- **Extension Modules**

### Extension Types:

Each operator's extensions remain local to their client. Multiplayers maintain their own toolset. No need to upload sensitive/custom tools to the server.

#### Beacon Object Files
- **Search Directories**: `cli/extensions/bof/`, `cli/extensions/`
- **File Extensions**: `.o`, `.bof`, `.x64.o`, `.x86.o`

#### .NET Assemblies
- **Search Directories**: `cli/extensions/assemblies/`, `cli/extensions/`
- **File Extensions**: `.exe`, `.dll`

#### PE Injection
- **Search Directories**: `cli/extensions/`, `cli/extensions/pe/`
- **File Extensions**: `.exe`, `.dll`

#### PowerShell Scripts
- **Search Directories**: `cli/extensions/powershell/`, `cli/extensions/`
- **File Extensions**: `.ps1`, `.psm1`, `.psd1`

#### Shellcode PInject
- **Search Directories**: `cli/extensions/`, `cli/extensions/shellcode/`
- **File Extensions**: `.b64`



---


