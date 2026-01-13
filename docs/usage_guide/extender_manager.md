# Extension Package Manager

The Neo C2 Extension Package Manager allows operators to install, manage, and update third-party tools and extensions directly from the client-side. This system is inspired by Sliver's armory package manager and provides similar functionality for the Neo C2 framework.

## Overview

The extension package manager enables operators to:
- Install extensions from remote repositories
- Manage installed packages
- Add custom repositories
- Verify package signatures for security
- Search for available extensions

## Commands

### Installation

Install a package from configured repositories:

```
extender install <package_name>
extensions install <package_name>
```

To force installation and overwrite existing packages:
```
extender install <package_name> --force
extender install <package_name> -f
```

### Listing Packages

List installed packages:
```
extender list
extensions list
```

List available packages from repositories:
```
extender list available
extensions list available
```

### Search Packages

Search for packages containing a specific term:
```
extender search <search_term>
extensions search <search_term>
```

### Uninstall Packages

Remove an installed package:
```
extender uninstall <package_name>
extensions uninstall <package_name>
```

### Update Packages

Update a package to the latest version:
```
extender update <package_name>
extensions update <package_name>
```

### Repository Management

Add a new repository:
```
extender add-repo <name> <url> <public_key>
extender add_repository <name> <url> <public_key>
```

Remove a repository:
```
extender remove-repo <name>
extender remove_repository <name>
extensions remove-repo <name>
```

## Configuration

The extension package manager uses a JSON configuration file located at `cli/extender_config.json`. This file contains:

- **repositories**: List of configured repositories with names, URLs, and public keys
- **installed_packages**: Tracking of currently installed packages
- **cache**: Cached package information for performance

### Default Configuration

The configuration is framework agnostic, any compatible extension library can be used e.g The Sliver Armory.

```json
{
  "repositories": [
    {
      "name": "Sliverarmory",
      "url": "https://api.github.com/repos/sliverarmory/armory/releases",
      "public_key": "RWSBpxpRWDrD7Fe+VvRE3c2VEDC2NK80rlNCj+BX0gz44Xw07r6KQD9L"
    }
  ],
  "installed_packages": {},
  "cache": {}
}
```

## Security Features

### Signature Verification

The package manager supports cryptographic signature verification using Ed25519 signatures. When available, packages are verified against the public key configured for each repository.

### Public Key Management

Each repository can have its own public key for signature verification. The system automatically verifies package signatures during installation when both the signature and public key are available.

## Package Types

The system supports different types of extensions organized in subdirectories by package name:

- **BOF (Beacon Object Files)**: `.o` files stored in `cli/extensions/bof/<package_name>/`
- **Assemblies**: .NET managed code files (`.exe` and `.dll`) stored in `cli/extensions/assemblies/<package_name>/`
- **PE Files**: Native executable files (`.exe` and `.dll`) stored in `cli/extensions/pe/<package_name>/`

### File Organization

When packages are installed, they are organized in the following directory structure:
```
cli/extensions/
├── bof/
│   └── <package_name>/
│       ├── <files>.o
│       └── <package_name>.json  # Optional metadata file
├── assemblies/
│   └── <package_name>/
│       ├── <files>.exe/.dll
│       └── <package_name>.json  # Optional metadata file
└── pe/
    └── <package_name>/
        ├── <files>.exe/.dll
        └── <package_name>.json  # Optional metadata file
```

### File Type Detection

The system automatically determines the file type based on naming conventions and extensions:

- **BOF files**: Always `.o` files
- **Assemblies**: `.exe` or `.dll` files with naming patterns like:
- **PE files**: Native executables with naming patterns like:

Assemblies and PE files are differentiated using:

- Repository Metadata (Highest Priority): Checks the type field in the repository JSON: "type": "assembly" or "type": "pe" and the is_dotnet field
- File Content Analysis: Involves PE Header Inspection, CLI Header Detection & Magic Value Check
- File Extension and Naming Conventions: Checks if the filename contains keywords like "assembly", "dotnet",etc -> treat as assembly and "native", "pe", "unmanaged, etc treat as PE

This allows the system to properly organize extensions based on their intended use and execution method.

## Repository Structure and Expected Format

The extension package manager is designed to work with GitHub releases as package repositories. The system expects:

### Repository Structure
- GitHub repository with releases
- Each release contains catalog JSON files (e.g., `extensions.json`, `catalog.json`, `armory.json` etc.)
- Catalog JSON files contain an "extensions" array with extension metadata

### Catalog JSON Format
The system dynamically finds any JSON file in releases that matches patterns like `extensions.json`, `catalog.json`, or `packages.json`. The JSON should contain:

```json
{
  "extensions": [
    {
      "name": "extension_name",
      "type": "bof|assembly|pe",
      "download_url": "https://direct-download-link.com/extension_archive.zip",
      "version": "1.0.0",
      "help": "Description of the extension",
      "is_dotnet": true|false  // for .NET assemblies
    },
    ...
  ],
  "bundles": [
     {
        "name": "bundle-name",
        "packages": [
           "extension1_name",
           "extension2_name"
        ]
     }
  ]
}
```

### Package Archive Format
The system handles download URLs in two ways:

#### Direct Download URLs
- Each `download_url` points to a compressed archive (`.zip` or `.tar.gz`)
- The archive contains the actual extension files and optional metadata files
- Archive structure example:
```
extension_archive.zip
├── extension_file.o          # For BOF extensions
├── extension_file.exe        # For assembly/PE extensions
├── extension_file.dll        # For assembly/PE extensions
└── extension_name.json       # Optional metadata file
```

#### GitHub Repository URLs (Recursive Resolution)
- If `download_url` points to a GitHub repository (e.g., `https://github.com/user/repo/releases`)
- The system will automatically resolve to find release assets
- It searches for the latest release with zip/tar.gz assets
- Downloads the first matching compressed archive it finds
- This allows for more flexible repository structures

### Recursive Resolution Process
When a `download_url` is identified as a GitHub repository URL:
1. The system converts the web URL to the GitHub API URL
2. Fetches the releases for that repository
3. Looks for assets with extensions `.zip`, `.tar.gz`, or `.tgz`
4. Downloads the first matching asset found
5. Proceeds with normal extraction and installation


### JSON Metadata File Format
When a corresponding JSON file is found in the archive (e.g., `whoami.json` for `whoami.x64.o`), it's stored in the same subdirectory as the extension and contains:
```json
{
  "version": "1.0.0",
  "help": "Description of the extension",
  "description": "Detailed description",
  "author": "Extension author",
  "repo_url": "https://github.com/author/repo"
}
```

## Usage Examples

### Install a Package
```
extender install whoami
```

### Search for Packages
```
extender search mimikatz
```

### List Available Packages
```
extender list available
```

### Add a Custom Repository
```
extender add-repo myrepo https://api.github.com/repos/myorg/myextensions/releases "my_public_key_here"
```

### Update an Extension
```
extender update whoami
```

### Uninstall an Extension
```
extender uninstall whoami
```


## Limitation
The system has a preference for x64 extensions when matching x64 and x86 extensions are encountered post-extraction;
e.g, `whoami.x86.o` and `whoami.x64.o`. To prevent system-breaking duplicates, only one of these would be installed im a folder 


## Troubleshooting

### Package Not Found

If a package cannot be found, verify:
- The package name is correct
- The repository is properly configured
- Internet connectivity is available
- The repository URL is accessible

### Signature Verification Failed

If signature verification fails:
- Verify the public key is correct
- Check that the package and signature files are from the same source
- Ensure the repository is trusted

### Installation Issues

For installation problems:
- Check that the target directories are writable
- Ensure the package format is supported
- Confirm the download URL is valid and accessible
