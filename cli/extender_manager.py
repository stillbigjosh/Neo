#!/usr/bin/env python3

"""
The Neo C2 Framework is a post-exploitation command and control framework.

This file is part of Neo C2 Framework.
Copyright (C) 2025 @stillbigjosh

The Neo C2 Framework of this edition is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

The Neo C2 Framework is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Neo.  If not, see <http://www.gnu.org/licenses/>
"""

import os
import json
import requests
import tempfile
import tarfile
import zipfile
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
import urllib.parse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import subprocess
import shutil
import re
import struct


# Initialize color support
try:
    from rich.console import Console
    from rich.text import Text
    from rich import print as rich_print
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False
    class Fore:
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        RESET = '\033[0m'

    class Back:
        pass

    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        RESET_ALL = '\033[0m'

def colored(text, color_code):
    if COLORS_ENABLED:
        return f"{color_code}{text}{Style.RESET_ALL}"
    return text

def red(text):
    return colored(text, Fore.RED)

def green(text):
    return colored(text, Fore.GREEN)

def yellow(text):
    return colored(text, Fore.YELLOW)

def blue(text):
    return colored(text, Fore.BLUE)

def magenta(text):
    return colored(text, Fore.MAGENTA)

def cyan(text):
    return colored(text, Fore.CYAN)

def bright(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if COLORS_ENABLED else text


class ExtensionPackage:
    def __init__(self, name: str, version: str, description: str, repo_url: str,
                 public_key: str, file_type: str, dependencies: List[str] = None,
                 signature_url: str = None, is_dotnet: bool = False):
        self.name = name
        self.version = version
        self.description = description
        self.repo_url = repo_url
        self.public_key = public_key
        self.file_type = file_type  # 'bof', 'assembly', 'pe', etc.
        self.dependencies = dependencies or []
        self.signature_url = signature_url
        self.is_dotnet = is_dotnet


class ExtensionPackageManager:

    def __init__(self, cli_instance):
        self.cli = cli_instance
        self.extensions_dir = Path("cli/extensions")
        self.bof_dir = self.extensions_dir / "bof"
        self.assemblies_dir = self.extensions_dir / "assemblies"
        self.pe_dir = self.extensions_dir / "pe"
        self.config_file = Path("cli/extender_config.json")

        # Create directories if they don't exist
        self.extensions_dir.mkdir(exist_ok=True)
        self.bof_dir.mkdir(exist_ok=True)
        self.assemblies_dir.mkdir(exist_ok=True)
        self.pe_dir.mkdir(exist_ok=True)

        # Load configuration
        self.config = self._load_config()

        # Initialize package cache
        self.package_cache = {}
        self._load_package_cache()

    def _load_config(self) -> Dict[str, Any]:
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{red('[-]')} Error loading config: {e}")

        # Default configuration if no config file exists
        default_config = {
            "repositories": [
                {
                    "name": "Neo Official",
                    "url": "",  # User must configure this
                    "public_key": ""  # User must configure this
                }
            ],
            "installed_packages": {},
            "cache": {}
        }

        # Save default config
        self._save_config(default_config)
        return default_config

    def _save_config(self, config: Dict[str, Any] = None):
        if config is None:
            config = self.config

        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"{red('[-]')} Error saving config: {e}")

    def _load_package_cache(self):
        self.package_cache = self.config.get("cache", {})

    def _save_package_cache(self):
        self.config["cache"] = self.package_cache
        self._save_config()

    def _extract_package_name_from_filename(self, filename: str) -> str:
        import re
        name = filename.lower()

        # Remove common architecture indicators
        name = re.sub(r'\.(x64|x86|amd64|arm|arm64)\.', '.', name)

        # Remove file extensions
        name = re.sub(r'\.(exe|dll|o|bof)$', '', name)

        return name

    def _get_version_and_description_from_json(self, json_file_path: Path) -> tuple:
        if json_file_path.exists():
            try:
                with open(json_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Try to get version and description from JSON
                version = data.get('version', 'N/A')
                description = data.get('help', data.get('description', 'N/A'))

                return version, description
            except Exception as e:
                print(f"{yellow('[*]')} Error reading JSON file {json_file_path}: {e}")
                return "N/A", "N/A"
        else:
            return "N/A", "N/A"

    def _is_dotnet_assembly(self, file_path: Path) -> bool:
        try:
            with open(file_path, 'rb') as f:
                # Read the DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64:
                    return False
                
                # Check for MZ signature
                if dos_header[:2] != b'MZ':
                    return False
                
                # Get the PE header offset from the DOS header
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                
                # Seek to the PE header
                f.seek(pe_offset)
                pe_header = f.read(24)
                
                if len(pe_header) < 24:
                    return False
                
                # Check for PE signature
                if pe_header[:4] != b'PE\x00\x00':
                    return False
                
                # Get the optional header magic
                optional_header_magic = struct.unpack('<H', pe_header[20:22])[0]
                
                # Calculate the offset to the data directories
                if optional_header_magic == 0x10b:  # PE32
                    data_dir_offset = pe_offset + 24 + 224  # Standard PE32 header size
                elif optional_header_magic == 0x20b:  # PE32+
                    data_dir_offset = pe_offset + 24 + 240  # Standard PE32+ header size
                else:
                    return False
                
                # Seek to the data directories (COFF header + optional header)
                f.seek(data_dir_offset)
                
                # Read the data directories (16 directories, each 8 bytes)
                data_dirs = f.read(16 * 8)
                
                if len(data_dirs) < 128:  # 16 * 8
                    return False
                
                # The 15th directory is the CLI header (COM+ header)
                cli_header_rva = struct.unpack('<I', data_dirs[14*8:14*8+4])[0]
                cli_header_size = struct.unpack('<I', data_dirs[14*8+4:14*8+8])[0]
                
                if cli_header_rva == 0 or cli_header_size == 0:
                    return False
                
                # Find the physical offset of the CLI header
                f.seek(0)
                sections = f.read()
                
                # Find the section that contains the CLI header RVA
                section_table_offset = data_dir_offset + 16 * 8
                f.seek(section_table_offset)
                
                # Read section headers (each is 40 bytes)
                section_count = struct.unpack('<H', pe_header[6:8])[0]
                
                cli_header_offset = None
                for i in range(section_count):
                    section_header = f.read(40)
                    if len(section_header) < 40:
                        break
                    
                    virtual_size = struct.unpack('<I', section_header[8:12])[0]
                    virtual_address = struct.unpack('<I', section_header[12:16])[0]
                    raw_size = struct.unpack('<I', section_header[16:20])[0]
                    raw_offset = struct.unpack('<I', section_header[20:24])[0]
                    
                    # Check if CLI header RVA falls within this section
                    if virtual_address <= cli_header_rva < virtual_address + virtual_size:
                        cli_header_offset = raw_offset + (cli_header_rva - virtual_address)
                        break
                
                if cli_header_offset is None:
                    return False
                
                # Read the CLI header
                f.seek(cli_header_offset)
                cli_header = f.read(72)  # CLI header is at least 72 bytes
                
                if len(cli_header) < 72:
                    return False
                
                # Check the CLI header magic (should be 0x48 if valid)
                cli_magic = struct.unpack('<I', cli_header[0:4])[0]
                if cli_magic != 0x48:
                    return False
                
                return True
                
        except Exception as e:
            print(f"{yellow('[*]')} Error checking .NET assembly: {e}")
            return False

    def _determine_file_type_by_content(self, file_path: Path) -> str:
        try:
            # Check if it's a .NET assembly by examining PE header
            if self._is_dotnet_assembly(file_path):
                return "assembly"
            
            # If it's a PE file but not .NET, it's a native PE
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                # Check for PE signature
                if b'PE\x00\x00' in header:
                    return "pe"
                
                # Check for BOF signature (typically starts with specific COFF headers)
                if header.startswith(b'\x4c\x01') or header.startswith(b'\x64\x86') or header.startswith(b'\x86\x64'):
                    return "bof"
                
        except Exception as e:
            print(f"{yellow('[*]')} Error determining file type by content: {e}")
        
        # If we can't determine by content, return unknown
        return "unknown"

    def _determine_file_type(self, asset_name: str, download_url: str = "", is_dotnet: bool = False, ext_type: str = "") -> str:
        # 1. Use the 'type' field from the repository JSON if available
        if ext_type:
            ext_type_lower = ext_type.lower()
            if ext_type_lower == "bof":
                return "bof"
            elif ext_type_lower in ["assembly", "dotnet"]:
                return "assembly"
            elif ext_type_lower in ["pe", "exe"]:
                return "pe"
        
        # 2. Use the 'is_dotnet' field from the repository JSON if available
        if is_dotnet:
            return "assembly"
        
        # 3. Use file extension from URL or asset name
        asset_lower = asset_name.lower()
        url_lower = download_url.lower()
        
        # Check extensions in URL or asset name
        for source in [url_lower, asset_lower]:
            if source.endswith('.o') or source.endswith('.bof'):
                return "bof"
            elif source.endswith(('.exe', '.dll')):
                # If it's an exe/dll, check if it's .NET based on naming or is_dotnet flag
                if any(keyword in source for keyword in ['assembly', 'dotnet', 'net', '.net']):
                    return "assembly"
                elif any(keyword in source for keyword in ['native', 'pe', 'unmanaged']):
                    return "pe"
                else:
                    # Default to PE for executables unless we have other indicators
                    return "pe"
        
        # 4. Use naming conventions as a fallback
        if any(keyword in asset_lower for keyword in ['assembly', 'dotnet', 'net', '.net']):
            return "assembly"
        elif any(keyword in asset_lower for keyword in ['bof', 'beacon']):
            return "bof"
        elif any(keyword in asset_lower for keyword in ['native', 'pe', 'unmanaged']):
            return "pe"
        
        # If all else fails, return unknown
        return "unknown"

    def _get_public_key_from_config(self) -> str:
        if self.config.get("repositories"):
            return self.config["repositories"][0].get("public_key", "")
        return ""

    def _verify_signature(self, data: bytes, signature_b64: str, public_key_b64: str) -> bool:
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            signature_bytes = base64.b64decode(signature_b64)

            # The public key should be 32 bytes for Ed25519
            if len(public_key_bytes) != 32:
                print(f"{red('[-]')} Invalid public key length: {len(public_key_bytes)}")
                return False

            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            try:
                public_key.verify(signature_bytes, data)
                return True
            except InvalidSignature:
                return False
        except Exception as e:
            print(f"{red('[-]')} Error verifying signature: {e}")
            return False

    def _download_package(self, package_url: str) -> bytes:
        try:
            print(f"{blue('[*]')} Downloading package from: {package_url}")
            response = requests.get(package_url, timeout=30)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"{red('[-]')} Error downloading package: {e}")
            raise

    def _download_signature(self, signature_url: str) -> Optional[str]:
        try:
            if not signature_url:
                return None
            print(f"{blue('[*]')} Downloading signature from: {signature_url}")
            response = requests.get(signature_url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"{yellow('[*]')} Error downloading signature: {e}")
            return None

    def _extract_package(self, package_data: bytes, extract_to: Path) -> bool:
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(package_data)
                temp_file_path = Path(temp_file.name)

            # Try to extract as tar.gz first, then as zip
            extracted = False
            try:
                with tarfile.open(temp_file_path, 'r:gz') as tar:
                    tar.extractall(path=extract_to)
                extracted = True
            except tarfile.ReadError:
                # Not a tar.gz file, try zip
                try:
                    with zipfile.ZipFile(temp_file_path, 'r') as zip_file:
                        zip_file.extractall(path=extract_to)
                    extracted = True
                except zipfile.BadZipFile:
                    print(f"{red('[-]')} Package is not a valid tar.gz or zip file")
                    extracted = False

            # Clean up temp file
            temp_file_path.unlink()
            return extracted
        except Exception as e:
            print(f"{red('[-]')} Error extracting package: {e}")
            if 'temp_file_path' in locals():
                temp_file_path.unlink(missing_ok=True)
            return False

    def _find_url_field(self, extension_data: dict) -> str:
        # Look for any field containing 'url' in the name (case-insensitive)
        for key, value in extension_data.items():
            if 'url' in key.lower():
                if isinstance(value, str) and value.startswith(('http://', 'https://')):
                    return value
        
        # If no URL field found, return empty string
        return ""

    def _convert_github_repo_to_api_url(self, repo_url: str) -> str:
        if "github.com" in repo_url:
            # Extract owner and repo from the URL
            parsed = urllib.parse.urlparse(repo_url)
            path_parts = parsed.path.strip('/').split('/')
            
            if len(path_parts) >= 2:
                owner = path_parts[0]
                repo = path_parts[1]
                return f"https://api.github.com/repos/{owner}/{repo}/releases"
        
        return repo_url

    def _find_download_url_from_github_release(self, repo_api_url: str, package_name: str) -> tuple:
        try:
            print(f"{blue('[*]')} Fetching GitHub releases from: {repo_api_url}")
            response = requests.get(repo_api_url, timeout=30)
            response.raise_for_status()
            releases = response.json()

            # Find the latest release with assets
            for release in releases:
                if release.get("prerelease", False) or release.get("draft", False):
                    continue

                assets = release.get("assets", [])
                
                # First, look for zip files or other extension packages (excluding .minisig files)
                for asset in assets:
                    asset_name = asset.get("name", "").lower()
                    
                    # Skip .minisig files
                    if asset_name.endswith('.minisig'):
                        continue
                    
                    # Look for assets that match the package name and are zip files
                    if package_name.lower() in asset_name and any(asset_name.endswith(ext) for ext in ['.zip', '.tar.gz', '.tgz']):
                        download_url = asset.get("browser_download_url", "")
                        if download_url:
                            version = release.get("tag_name", "unknown")
                            description = release.get("body", "")
                            return download_url, version, description
                
                # Look for assets that might contain the package name in a different format (excluding .minisig)
                for asset in assets:
                    asset_name = asset.get("name", "").lower()
                    
                    # Skip .minisig files
                    if asset_name.endswith('.minisig'):
                        continue
                    
                    if any(name in asset_name for name in [package_name.lower(), package_name.lower().replace('-', ''), package_name.lower().replace('_', '')]):
                        download_url = asset.get("browser_download_url", "")
                        if download_url:
                            version = release.get("tag_name", "unknown")
                            description = release.get("body", "")
                            return download_url, version, description

                # If we found assets but none matched the package name, try the first valid zip asset (excluding .minisig)
                for asset in assets:
                    asset_name = asset.get("name", "").lower()
                    
                    # Skip .minisig files
                    if asset_name.endswith('.minisig'):
                        continue
                    
                    if any(asset_name.endswith(ext) for ext in ['.zip', '.tar.gz', '.tgz']):
                        download_url = asset.get("browser_download_url", "")
                        if download_url:
                            version = release.get("tag_name", "unknown")
                            description = release.get("body", "")
                            return download_url, version, description

        except Exception as e:
            print(f"{yellow('[*]')} Error fetching GitHub releases: {e}")
        
        return "", "unknown", ""

    def _get_package_info_from_repo(self, package_name: str) -> Optional[ExtensionPackage]:
        for repo in self.config.get("repositories", []):
            try:
                # For GitHub releases API (like Sliver armory)
                if "github.com" in repo["url"] or "api.github.com" in repo["url"]:
                    # For Sliver-style armory, we need to get the armory.json file
                    # which contains the catalog of all available extensions
                    releases_url = repo["url"]
                    response = requests.get(releases_url, timeout=30)
                    response.raise_for_status()

                    releases = response.json()

                    # Find the latest release with armory.json
                    for release in releases:
                        if release.get("prerelease", False) or release.get("draft", False):
                            continue

                        release_assets = release.get("assets", [])

                        # Look for any JSON catalog file - make it dynamic to work with different formats
                        catalog_json_asset = None
                        for asset in release_assets:
                            asset_name = asset.get("name", "").lower()
                            # Look for any JSON file that could contain extension info
                            if asset_name.endswith('.json') and any(name in asset_name for name in ['armory', 'extensions', 'catalog', 'packages', 'repo', 'index']):
                                catalog_json_asset = asset
                                break

                        # If no specific catalog file found, try any JSON file
                        if not catalog_json_asset:
                            for asset in release_assets:
                                if asset.get("name", "").lower().endswith('.json'):
                                    catalog_json_asset = asset
                                    break

                        if catalog_json_asset:
                            # Download and parse the catalog JSON file
                            catalog_json_url = catalog_json_asset.get("browser_download_url", "")
                            if catalog_json_url:
                                catalog_response = requests.get(catalog_json_url, timeout=30)
                                catalog_response.raise_for_status()
                                catalog_data = catalog_response.json()

                                # Look for the specific package in the extensions list
                                extensions = catalog_data.get("extensions", [])
                                if not extensions:
                                    # Try other possible keys for extensions list
                                    for key in ['packages', 'extensions', 'tools', 'commands', 'modules']:
                                        if key in catalog_data:
                                            extensions = catalog_data[key]
                                            break

                                for ext in extensions:
                                    name = ext.get("name", "")
                                    if package_name.lower() in name.lower() or name.lower() in package_name.lower():
                                        # Get the download URL dynamically - look for any field containing 'url'
                                        download_url = self._find_url_field(ext)
                                        if not download_url:
                                            # Fallback to common field names
                                            download_url = ext.get("download_url", "")
                                            if not download_url:
                                                download_url = ext.get("url", "")
                                            if not download_url:
                                                download_url = ext.get("uri", "")

                                        # If download_url is still empty, try to convert repo_url to API URL and find assets
                                        if not download_url and ext.get("repo_url", ""):
                                            repo_api_url = self._convert_github_repo_to_api_url(ext.get("repo_url", ""))
                                            if repo_api_url:
                                                download_url, version, description = self._find_download_url_from_github_release(repo_api_url, name)
                                                if download_url:
                                                    # Update the version and description from GitHub release if not in the original data
                                                    if version != "unknown":
                                                        ext.setdefault("version", version)
                                                    if description:
                                                        ext.setdefault("description", description)
                                                        ext.setdefault("help", description)

                                        # Get type and is_dotnet from the extension data
                                        ext_type = ext.get("type", "")
                                        is_dotnet = ext.get("is_dotnet", False)

                                        # Determine file type using the enhanced method
                                        file_type = self._determine_file_type(
                                            name, 
                                            download_url, 
                                            is_dotnet, 
                                            ext_type
                                        )

                                        return ExtensionPackage(
                                            name=name,
                                            version=ext.get("version", release.get("tag_name", "unknown")),
                                            description=ext.get("help", ext.get("description", "")),
                                            repo_url=download_url,
                                            public_key=repo.get("public_key", ""),
                                            file_type=file_type,
                                            is_dotnet=is_dotnet
                                        )
                                break  # Only process the first catalog JSON we find
            except Exception as e:
                print(f"{yellow('[*]')} Error fetching from repository {repo['name']}: {e}")
                continue

        return None

    def _get_available_packages(self) -> List[ExtensionPackage]:
        packages = []

        for repo in self.config.get("repositories", []):
            try:
                # For GitHub releases API (like Sliver armory)
                if "github.com" in repo["url"] or "api.github.com" in repo["url"]:
                    # For Sliver-style armory, we need to get the armory.json file
                    # which contains the catalog of all available extensions
                    releases_url = repo["url"]
                    response = requests.get(releases_url, timeout=30)
                    response.raise_for_status()

                    releases = response.json()

                    # Find the latest release with armory.json
                    for release in releases:
                        if release.get("prerelease", False) or release.get("draft", False):
                            continue

                        release_assets = release.get("assets", [])

                        # Look for any JSON catalog file - make it dynamic to work with different formats
                        catalog_json_asset = None
                        for asset in release_assets:
                            asset_name = asset.get("name", "").lower()
                            # Look for any JSON file that could contain extension info
                            if asset_name.endswith('.json') and any(name in asset_name for name in ['armory', 'extensions', 'catalog', 'packages', 'repo', 'index']):
                                catalog_json_asset = asset
                                break

                        # If no specific catalog file found, try any JSON file
                        if not catalog_json_asset:
                            for asset in release_assets:
                                if asset.get("name", "").lower().endswith('.json'):
                                    catalog_json_asset = asset
                                    break

                        if catalog_json_asset:
                            # Download and parse the catalog JSON file
                            catalog_json_url = catalog_json_asset.get("browser_download_url", "")
                            if catalog_json_url:
                                catalog_response = requests.get(catalog_json_url, timeout=30)
                                catalog_response.raise_for_status()
                                catalog_data = catalog_response.json()

                                # Parse the extensions from the catalog JSON
                                extensions = catalog_data.get("extensions", [])
                                if not extensions:
                                    # Try other possible keys for extensions list
                                    for key in ['packages', 'extensions', 'tools', 'commands', 'modules']:
                                        if key in catalog_data:
                                            extensions = catalog_data[key]
                                            break

                                for ext in extensions:
                                    name = ext.get("name", "")
                                    if name:
                                        # Get the download URL dynamically - look for any field containing 'url'
                                        download_url = self._find_url_field(ext)
                                        if not download_url:
                                            # Fallback to common field names
                                            download_url = ext.get("download_url", "")
                                            if not download_url:
                                                download_url = ext.get("url", "")
                                            if not download_url:
                                                download_url = ext.get("uri", "")

                                        # If download_url is still empty, try to convert repo_url to API URL and find assets
                                        if not download_url and ext.get("repo_url", ""):
                                            repo_api_url = self._convert_github_repo_to_api_url(ext.get("repo_url", ""))
                                            if repo_api_url:
                                                found_url, version, description = self._find_download_url_from_github_release(repo_api_url, name)
                                                if found_url:
                                                    download_url = found_url
                                                    # Update the version and description from GitHub release if not in the original data
                                                    if version != "unknown":
                                                        ext.setdefault("version", version)
                                                    if description:
                                                        ext.setdefault("description", description)
                                                        ext.setdefault("help", description)

                                        # Get type and is_dotnet from the extension data
                                        ext_type = ext.get("type", "")
                                        is_dotnet = ext.get("is_dotnet", False)

                                        # Determine file type using the enhanced method
                                        file_type = self._determine_file_type(
                                            name, 
                                            download_url, 
                                            is_dotnet, 
                                            ext_type
                                        )

                                        package = ExtensionPackage(
                                            name=name,
                                            version=ext.get("version", release.get("tag_name", "unknown")),
                                            description=ext.get("help", ext.get("description", "")),
                                            repo_url=download_url,
                                            public_key=repo.get("public_key", ""),
                                            file_type=file_type,
                                            is_dotnet=is_dotnet
                                        )
                                        packages.append(package)
                                break  # Only process the first catalog JSON we find
            except Exception as e:
                print(f"{yellow('[*]')} Error fetching packages from repository {repo['name']}: {e}")
                continue

        return packages

    def list_available_packages(self):
        print(f"{green('[+]')} Available packages:")
        print("-" * 80)
        print(f"{'Name':<20} {'Version':<10} {'Type':<10} {'Description':<35}")
        print("-" * 80)

        packages = self._get_available_packages()
        for pkg in packages:
            description = pkg.description[:32] + "..." if len(pkg.description) > 32 else pkg.description
            print(f"{pkg.name:<20} {pkg.version:<10} {pkg.file_type.upper():<10} {description:<35}")

        print("-" * 80)
        print(f"Total: {len(packages)} packages available")

    def list_installed_packages(self):
        print(f"{green('[+]')} Installed packages:")
        print("-" * 120)
        print(f"{'Name':<20} {'Version':<15} {'Type':<10} {'Description':<60}")
        print("-" * 120)

        installed_count = 0

        # Check BOF directory for package subdirectories (new structure)
        for package_dir in self.bof_dir.iterdir():
            if package_dir.is_dir():
                # Look for BOF files in the package directory
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.o', '.bof']:
                        pkg_name = package_dir.name  # Use directory name as package name
                        # Try to get version and description from JSON file in the same directory
                        json_file_path = package_dir / f"{pkg_name}.json"
                        version, description = self._get_version_and_description_from_json(json_file_path)
                        if version == "N/A":
                            # Fallback to config if not found in JSON
                            version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                        if description == "N/A":
                            description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                        print(f"{pkg_name:<20} {version:<15} {'BOF':<10} {description:<60}")
                        installed_count += 1

        # Check BOF directory for legacy flat structure files (not in subdirectories)
        for file_path in self.bof_dir.glob("*"):
            if file_path.is_file() and file_path.suffix in ['.o', '.bof']:
                # Extract package name from filename (e.g., whoami.x64.o -> whoami)
                pkg_name = self._extract_package_name_from_filename(file_path.name)
                # Try to get version and description from JSON file in the same directory
                json_file_path = file_path.parent / f"{pkg_name}.json"
                version, description = self._get_version_and_description_from_json(json_file_path)
                if version == "N/A":
                    # Fallback to config if not found in JSON
                    version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                if description == "N/A":
                    description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                print(f"{pkg_name:<20} {version:<15} {'BOF':<10} {description:<60}")
                installed_count += 1

        # Check Assemblies directory for package subdirectories (new structure)
        for package_dir in self.assemblies_dir.iterdir():
            if package_dir.is_dir():
                # Look for assembly files in the package directory
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.exe', '.dll']:
                        pkg_name = package_dir.name  # Use directory name as package name
                        # Try to get version and description from JSON file in the same directory
                        json_file_path = package_dir / f"{pkg_name}.json"
                        version, description = self._get_version_and_description_from_json(json_file_path)
                        if version == "N/A":
                            # Fallback to config if not found in JSON
                            version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                        if description == "N/A":
                            description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                        print(f"{pkg_name:<20} {version:<15} {'ASSEMBLY':<10} {description:<60}")
                        installed_count += 1

        # Check Assemblies directory for legacy flat structure files
        for file_path in self.assemblies_dir.glob("*"):
            if file_path.is_file() and file_path.suffix in ['.exe', '.dll']:
                pkg_name = self._extract_package_name_from_filename(file_path.name)
                # Try to get version and description from JSON file in the same directory
                json_file_path = file_path.parent / f"{pkg_name}.json"
                version, description = self._get_version_and_description_from_json(json_file_path)
                if version == "N/A":
                    # Fallback to config if not found in JSON
                    version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                if description == "N/A":
                    description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                print(f"{pkg_name:<20} {version:<15} {'ASSEMBLY':<10} {description:<60}")
                installed_count += 1

        # Check PE directory for package subdirectories (new structure)
        for package_dir in self.pe_dir.iterdir():
            if package_dir.is_dir():
                # Look for PE files in the package directory
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.exe', '.dll']:
                        pkg_name = package_dir.name  # Use directory name as package name
                        # Try to get version and description from JSON file in the same directory
                        json_file_path = package_dir / f"{pkg_name}.json"
                        version, description = self._get_version_and_description_from_json(json_file_path)
                        if version == "N/A":
                            # Fallback to config if not found in JSON
                            version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                        if description == "N/A":
                            description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                        print(f"{pkg_name:<20} {version:<15} {'PE':<10} {description:<60}")
                        installed_count += 1

        # Check PE directory for legacy flat structure files
        for file_path in self.pe_dir.glob("*"):
            if file_path.is_file() and file_path.suffix in ['.exe', '.dll']:
                pkg_name = self._extract_package_name_from_filename(file_path.name)
                # Try to get version and description from JSON file in the same directory
                json_file_path = file_path.parent / f"{pkg_name}.json"
                version, description = self._get_version_and_description_from_json(json_file_path)
                if version == "N/A":
                    # Fallback to config if not found in JSON
                    version = self.config["installed_packages"].get(pkg_name, {}).get("version", "N/A")
                if description == "N/A":
                    description = self.config["installed_packages"].get(pkg_name, {}).get("description", "N/A")
                print(f"{pkg_name:<20} {version:<15} {'PE':<10} {description:<60}")
                installed_count += 1

        print("-" * 120)
        print(f"Total: {installed_count} packages installed")

    def install_package(self, package_name: str, force: bool = False):
        print(f"{blue('[*]')} Searching for package: {package_name}")

        # Get package info
        pkg_info = self._get_package_info_from_repo(package_name)
        if not pkg_info:
            print(f"{red('[-]')} Package '{package_name}' not found in any repository")
            return False

        print(f"{green('[+]')} Found package: {pkg_info.name} v{pkg_info.version} ({pkg_info.file_type})")

        # Check if already installed
        if not force and self._is_package_installed(pkg_info):
            print(f"{yellow('[*]')} Package '{pkg_info.name}' is already installed. Use --force to overwrite.")
            return False

        try:
            # Check if repo_url is empty
            if not pkg_info.repo_url:
                print(f"{red('[-]')} No download URL available for package '{pkg_info.name}'")
                return False

            # Check if the repo_url is a GitHub repository URL and needs to be resolved to a release asset
            package_data = self._resolve_and_download_package(pkg_info.repo_url)
            if package_data is None:
                print(f"{red('[-]')} Failed to download package from '{pkg_info.repo_url}'")
                return False

            # Download signature if available
            signature_data = None
            if pkg_info.signature_url:
                signature_data = self._download_signature(pkg_info.signature_url)

            # Verify signature if both package and signature are available
            if signature_data and pkg_info.public_key:
                print(f"{blue('[*]')} Verifying package signature...")
                if not self._verify_signature(package_data, signature_data, pkg_info.public_key):
                    print(f"{red('[-]')} Package signature verification failed!")
                    return False
                print(f"{green('[+]')} Package signature verified successfully")
            else:
                print(f"{yellow('[*]')} Skipping signature verification (signature or public key not available)")

            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Extract the package
                if self._extract_package(package_data, temp_path):
                    # Install the extracted files to the appropriate directory
                    success = self._install_extracted_files(temp_path, pkg_info.file_type, pkg_info.name)
                    if success:
                        # Determine the actual file type after extraction if it was unknown
                        actual_file_type = pkg_info.file_type
                        if pkg_info.file_type == "unknown":
                            # Look at the extracted files to determine the actual type
                            for file_path in (temp_path / pkg_info.name).rglob("*") if (temp_path / pkg_info.name).exists() else temp_path.rglob("*"):
                                if file_path.is_file():
                                    if file_path.suffix == '.o':
                                        actual_file_type = "bof"
                                        break
                                    elif file_path.suffix in ['.exe', '.dll']:
                                        if self._is_dotnet_assembly(file_path):
                                            actual_file_type = "assembly"
                                        else:
                                            actual_file_type = "pe"
                                        break

                        # Update installed packages in config
                        self.config["installed_packages"][pkg_info.name] = {
                            "version": pkg_info.version,
                            "type": actual_file_type,
                            "repo_url": pkg_info.repo_url,
                            "installed_at": str(self.extensions_dir),
                            "signature_verified": bool(signature_data),
                            "description": pkg_info.description,
                            "is_dotnet": pkg_info.is_dotnet
                        }
                        self._save_config()
                        print(f"{green('[+]')} Package '{pkg_info.name}' installed successfully")
                        return True
                    else:
                        print(f"{red('[-]')} Failed to install extracted files")
                        return False
                else:
                    print(f"{red('[-]')} Failed to extract package")
                    return False
        except Exception as e:
            print(f"{red('[-]')} Error installing package: {e}")
            return False

    def _resolve_and_download_package(self, repo_url: str) -> Optional[bytes]:
        # Check if it's a GitHub repository URL
        if "github.com" in repo_url and "/releases" in repo_url:
            # This might be a GitHub releases page URL, try to get the latest release assets
            try:
                # Convert GitHub releases page URL to API URL
                # e.g., https://github.com/user/repo/releases -> https://api.github.com/repos/user/repo/releases
                parts = repo_url.replace("https://github.com/", "").split("/")
                if len(parts) >= 3:
                    owner = parts[0]
                    repo = parts[1]
                    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"

                    response = requests.get(api_url, timeout=30)
                    response.raise_for_status()
                    releases = response.json()

                    # Look for the latest release with assets
                    for release in releases:
                        if release.get("prerelease", False) or release.get("draft", False):
                            continue

                        assets = release.get("assets", [])
                        # Look for zip files or other extension packages (excluding .minisig files)
                        for asset in assets:
                            asset_name = asset.get("name", "").lower()
                            
                            # Skip .minisig files
                            if asset_name.endswith('.minisig'):
                                continue
                            
                            if any(asset_name.endswith(ext) for ext in ['.zip', '.tar.gz', '.tgz']):
                                # Found a potential package file, download it
                                download_url = asset.get("browser_download_url", "")
                                if download_url:
                                    print(f"{blue('[*]')} Found package asset: {asset.get('name', '')}")
                                    return self._download_package(download_url)

                    # If no zip asset found in releases, return None
                    print(f"{yellow('[*]')} No zip assets found in releases")
                    return None
            except Exception as e:
                print(f"{yellow('[*]')} Could not resolve GitHub URL: {e}")
                # If GitHub resolution fails, fall back to direct download

        # If it's a GitHub repository URL but not a releases URL, convert to API and find assets
        elif "github.com" in repo_url and "/releases" not in repo_url:
            try:
                api_url = self._convert_github_repo_to_api_url(repo_url)
                if api_url:
                    download_url, _, _ = self._find_download_url_from_github_release(api_url, "")
                    if download_url:
                        return self._download_package(download_url)
            except Exception as e:
                print(f"{yellow('[*]')} Could not resolve GitHub repo URL to releases: {e}")

        # If not a GitHub URL or resolution failed, try direct download
        try:
            return self._download_package(repo_url)
        except Exception as e:
            print(f"{red('[-]')} Error downloading from direct URL: {e}")
            return None

    def _is_package_installed(self, pkg_info: ExtensionPackage) -> bool:
        # Check if the package directory exists (new structure)
        if pkg_info.file_type == "bof":
            package_dir = self.bof_dir / pkg_info.name
            if package_dir.exists():
                # Check if it contains the expected file types
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.o', '.bof']:
                        return True
            # Also check legacy flat structure
            for file_path in self.bof_dir.glob(f"{pkg_info.name}.*"):
                if file_path.suffix in ['.o', '.bof']:
                    return True
        elif pkg_info.file_type == "assembly":
            package_dir = self.assemblies_dir / pkg_info.name
            if package_dir.exists():
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.exe', '.dll']:
                        return True
            # Also check legacy flat structure
            for file_path in self.assemblies_dir.glob(f"{pkg_info.name}.*"):
                if file_path.suffix in ['.exe', '.dll']:
                    return True
        elif pkg_info.file_type == "pe":
            package_dir = self.pe_dir / pkg_info.name
            if package_dir.exists():
                for file_path in package_dir.glob("*"):
                    if file_path.suffix in ['.exe', '.dll']:
                        return True
            # Also check legacy flat structure
            for file_path in self.pe_dir.glob(f"{pkg_info.name}.*"):
                if file_path.suffix in ['.exe', '.dll']:
                    return True

        return False

    def _install_extracted_files(self, extract_path: Path, file_type: str, package_name: str = None) -> bool:
        try:
            # If file_type is unknown, determine it from the extracted files
            if file_type == "unknown":
                # Scan the extracted files to determine the actual file types
                for file_path in extract_path.rglob("*"):
                    if file_path.is_file():
                        if file_path.suffix == '.o':
                            file_type = "bof"
                            break
                        elif file_path.suffix in ['.exe', '.dll']:
                            # Determine if it's assembly or PE based on content
                            if self._is_dotnet_assembly(file_path):
                                file_type = "assembly"
                            else:
                                file_type = "pe"
                            break

            target_base_dir = None
            if file_type == "bof":
                target_base_dir = self.bof_dir
            elif file_type == "assembly":
                target_base_dir = self.assemblies_dir
            elif file_type == "pe":
                target_base_dir = self.pe_dir
            else:
                print(f"{red('[-]')} Unknown file type: {file_type}")
                return False

            # Create a subdirectory for the package
            if package_name:
                package_dir = target_base_dir / package_name
            else:
                # If no package name provided, use a generic name
                package_dir = target_base_dir / "unknown_package"

            package_dir.mkdir(exist_ok=True)

            # Copy all files from extract_path to package directory
            for file_path in extract_path.rglob("*"):
                if file_path.is_file():
                    # Check if it's a supported file type
                    if file_path.suffix in ['.o', '.exe', '.dll', '.bof']:
                        target_file = package_dir / file_path.name
                        shutil.copy2(file_path, target_file)
                        print(f"{green('[+]')} Copied {file_path.name} to {package_dir}")

            return True
        except Exception as e:
            print(f"{red('[-]')} Error installing files: {e}")
            return False

    def uninstall_package(self, package_name: str):
        print(f"{blue('[*]')} Uninstalling package: {package_name}")

        # Find and remove package directory (new structure) and legacy files
        removed_count = 0

        # Check BOF directory for package subdirectory (new structure)
        package_bof_dir = self.bof_dir / package_name
        if package_bof_dir.exists():
            for file_path in package_bof_dir.glob("*"):
                if file_path.suffix in ['.o', '.bof']:
                    file_path.unlink()
                    print(f"{green('[+]')} Removed {file_path.name}")
                    removed_count += 1
            # Remove the empty directory
            try:
                package_bof_dir.rmdir()
                print(f"{green('[+]')} Removed directory {package_bof_dir}")
            except OSError:
                # Directory not empty or other error
                print(f"{yellow('[*]')} Could not remove directory {package_bof_dir} (may not be empty)")

        # Also check for legacy flat structure files in BOF directory
        for file_path in self.bof_dir.glob(f"{package_name}.*"):
            if file_path.suffix in ['.o', '.bof']:
                file_path.unlink()
                print(f"{green('[+]')} Removed {file_path.name}")
                removed_count += 1

        # Check Assemblies directory for package subdirectory (new structure)
        package_assembly_dir = self.assemblies_dir / package_name
        if package_assembly_dir.exists():
            for file_path in package_assembly_dir.glob("*"):
                if file_path.suffix in ['.exe', '.dll']:
                    file_path.unlink()
                    print(f"{green('[+]')} Removed {file_path.name}")
                    removed_count += 1
            # Remove the empty directory
            try:
                package_assembly_dir.rmdir()
                print(f"{green('[+]')} Removed directory {package_assembly_dir}")
            except OSError:
                # Directory not empty or other error
                print(f"{yellow('[*]')} Could not remove directory {package_assembly_dir} (may not be empty)")

        # Also check for legacy flat structure files in Assemblies directory
        for file_path in self.assemblies_dir.glob(f"{package_name}.*"):
            if file_path.suffix in ['.exe', '.dll']:
                file_path.unlink()
                print(f"{green('[+]')} Removed {file_path.name}")
                removed_count += 1

        # Check PE directory for package subdirectory (new structure)
        package_pe_dir = self.pe_dir / package_name
        if package_pe_dir.exists():
            for file_path in package_pe_dir.glob("*"):
                if file_path.suffix in ['.exe', '.dll']:
                    file_path.unlink()
                    print(f"{green('[+]')} Removed {file_path.name}")
                    removed_count += 1
            # Remove the empty directory
            try:
                package_pe_dir.rmdir()
                print(f"{green('[+]')} Removed directory {package_pe_dir}")
            except OSError:
                # Directory not empty or other error
                print(f"{yellow('[*]')} Could not remove directory {package_pe_dir} (may not be empty)")

        # Also check for legacy flat structure files in PE directory
        for file_path in self.pe_dir.glob(f"{package_name}.*"):
            if file_path.suffix in ['.exe', '.dll']:
                file_path.unlink()
                print(f"{green('[+]')} Removed {file_path.name}")
                removed_count += 1

        if removed_count > 0:
            # Remove from installed packages config
            if package_name in self.config["installed_packages"]:
                del self.config["installed_packages"][package_name]
                self._save_config()
            print(f"{green('[+]')} Removed {removed_count} files for package '{package_name}'")
        else:
            print(f"{yellow('[*]')} Package '{package_name}' not found or already removed")

    def update_package(self, package_name: str):
        print(f"{blue('[*]')} Updating package: {package_name}")

        # First check if package is installed
        if not self._is_package_installed(ExtensionPackage(package_name, "", "", "", "", "bof")):
            print(f"{red('[-]')} Package '{package_name}' is not installed")
            return False

        # Install with force to overwrite
        return self.install_package(package_name, force=True)

    def search_packages(self, search_term: str):
        print(f"{green('[+]')} Searching for packages containing: {search_term}")
        print("-" * 80)
        print(f"{'Name':<20} {'Version':<10} {'Type':<10} {'Description':<35}")
        print("-" * 80)

        packages = self._get_available_packages()
        matches = [pkg for pkg in packages if search_term.lower() in pkg.name.lower()]

        for pkg in matches:
            description = pkg.description[:32] + "..." if len(pkg.description) > 32 else pkg.description
            print(f"{pkg.name:<20} {pkg.version:<10} {pkg.file_type.upper():<10} {description:<35}")

        print("-" * 80)
        print(f"Found: {len(matches)} matching packages")

    def add_repository(self, name: str, url: str, public_key: str):
        new_repo = {
            "name": name,
            "url": url,
            "public_key": public_key
        }

        # Check if repository already exists
        for repo in self.config.get("repositories", []):
            if repo["name"] == name:
                print(f"{yellow('[*]')} Repository '{name}' already exists")
                return False

        self.config.setdefault("repositories", []).append(new_repo)
        self._save_config()
        print(f"{green('[+]')} Added repository: {name}")
        return True

    def remove_repository(self, name: str):
        repositories = self.config.get("repositories", [])
        updated_repos = [repo for repo in repositories if repo["name"] != name]

        if len(updated_repos) == len(repositories):
            print(f"{red('[-]')} Repository '{name}' not found")
            return False

        self.config["repositories"] = updated_repos
        self._save_config()
        print(f"{green('[+]')} Removed repository: {name}")
        return True
