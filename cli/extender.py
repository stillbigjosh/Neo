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
import re
import json
from pathlib import Path

# Initialize color support for the extender
try:
    from rich.console import Console
    from rich.text import Text
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
        pass  # Add background colors if needed later

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


class CLIExtender:
    
    def __init__(self, cli_instance):
        self.cli = cli_instance
        self.extensions_dir = Path("cli/extensions")
        self.bof_dir = self.extensions_dir / "bof"
        self.assemblies_dir = self.extensions_dir / "assemblies"
        self.pe_dir = self.extensions_dir / "pe"

        # Dictionary to store command name to file mapping
        self.command_registry = {}

        # Load and register all available extensions
        self._load_extensions()
    
    def _load_extensions(self):
        print(f"[+] Loading extensions from {self.extensions_dir}")

        # Register BOF files
        self._register_bof_files()

        # Register assembly files
        self._register_assembly_files()

        # Register PE files
        self._register_pe_files()

        print(f"[+] Registered {len(self.command_registry)} extension commands")
    
    def _register_bof_files(self):
        if not self.bof_dir.exists():
            print(f"[-] BOF directory does not exist: {self.bof_dir}")
            return

        print(f"[*] Scanning BOF directory: {self.bof_dir}")

        for file_path in self.bof_dir.glob("*.o"):
            command_name = self._extract_command_name(file_path.name)
            if command_name:
                # Load JSON metadata if available - look for JSON file with the same base name as the command
                json_file_path = file_path.parent / f"{command_name}.json"
                metadata = self._load_json_metadata(json_file_path) if json_file_path.exists() else {}

                self.command_registry[command_name] = {
                    'type': 'bof',
                    'file_path': str(file_path),
                    'original_name': file_path.name,
                    'metadata': metadata
                }
                #print(f"[+] Registered BOF command: {command_name} -> {file_path.name}")
    
    def _register_assembly_files(self):
        if not self.assemblies_dir.exists():
            print(f"[-] Assemblies directory does not exist: {self.assemblies_dir}")
            return

        print(f"[*] Scanning Assemblies directory: {self.assemblies_dir}")

        for file_path in self.assemblies_dir.glob("*.exe"):
            command_name = self._extract_command_name(file_path.name)
            if command_name:
                # Load JSON metadata if available - look for JSON file with the same base name as the command
                json_file_path = file_path.parent / f"{command_name}.json"
                metadata = self._load_json_metadata(json_file_path) if json_file_path.exists() else {}

                self.command_registry[command_name] = {
                    'type': 'assembly',
                    'file_path': str(file_path),
                    'original_name': file_path.name,
                    'metadata': metadata
                }
                #print(f"[+] Registered Assembly command: {command_name} -> {file_path.name}")

        for file_path in self.assemblies_dir.glob("*.dll"):
            command_name = self._extract_command_name(file_path.name)
            if command_name:
                # Load JSON metadata if available - look for JSON file with the same base name as the command
                json_file_path = file_path.parent / f"{command_name}.json"
                metadata = self._load_json_metadata(json_file_path) if json_file_path.exists() else {}

                self.command_registry[command_name] = {
                    'type': 'assembly',
                    'file_path': str(file_path),
                    'original_name': file_path.name,
                    'metadata': metadata
                }
                #print(f"[+] Registered Assembly command: {command_name} -> {file_path.name}")

    def _register_pe_files(self):
        if not self.pe_dir.exists():
            print(f"[-] PE directory does not exist: {self.pe_dir}")
            return

        print(f"[*] Scanning PE directory: {self.pe_dir}")

        for file_path in self.pe_dir.glob("*.exe"):
            command_name = self._extract_command_name(file_path.name)
            if command_name:
                # Load JSON metadata if available - look for JSON file with the same base name as the command
                json_file_path = file_path.parent / f"{command_name}.json"
                metadata = self._load_json_metadata(json_file_path) if json_file_path.exists() else {}

                self.command_registry[command_name] = {
                    'type': 'pe',
                    'file_path': str(file_path),
                    'original_name': file_path.name,
                    'metadata': metadata
                }
                #print(f"[+] Registered PE command: {command_name} -> {file_path.name}")

        for file_path in self.pe_dir.glob("*.dll"):
            command_name = self._extract_command_name(file_path.name)
            if command_name:
                # Load JSON metadata if available - look for JSON file with the same base name as the command
                json_file_path = file_path.parent / f"{command_name}.json"
                metadata = self._load_json_metadata(json_file_path) if json_file_path.exists() else {}

                self.command_registry[command_name] = {
                    'type': 'pe',
                    'file_path': str(file_path),
                    'original_name': file_path.name,
                    'metadata': metadata
                }
                #print(f"[+] Registered PE command: {command_name} -> {file_path.name}")

    def _extract_command_name(self, filename):
        # Remove .x64, .x86, .exe, .dll, .o extensions in order
        name = filename.lower()

        # Remove common architecture indicators
        name = re.sub(r'\.(x64|x86|amd64|arm|arm64)\.', '.', name)

        # Remove file extensions
        name = re.sub(r'\.(exe|dll|o)$', '', name)

        # Return the command name if it's valid (not empty and contains only alphanumeric, underscore, hyphen)
        if name and re.match(r'^[a-z0-9_-]+$', name):
            return name
        return None

    def _load_json_metadata(self, json_file_path):
        """Load metadata from JSON file"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            return metadata
        except Exception as e:
            print(f"{red('[-]')} Error loading metadata from {json_file_path}: {str(e)}")
            return {}
    
    def is_extension_command(self, command):
        command_parts = command.strip().split()
        if not command_parts:
            return False
        
        command_name = command_parts[0].lower()
        return command_name in self.command_registry
    
    def handle_extension_command(self, command):
        command_parts = command.strip().split()
        if not command_parts:
            return None

        command_name = command_parts[0].lower()

        if command_name not in self.command_registry:
            return None

        extension_info = self.command_registry[command_name]

        # Get the actual file path
        file_path = extension_info['file_path']

        # Read the file content and base64 encode it (similar to _handle_extension_command)
        import os
        import base64

        # Define search paths similar to _handle_extension_command
        if extension_info['type'] == 'bof':
            search_paths = [
                file_path,  # Direct path from registry
                os.path.join('cli', 'extensions', 'bof', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
                os.path.join(os.getcwd(), file_path),
                os.path.join(os.getcwd(), os.path.basename(file_path))
            ]
        elif extension_info['type'] == 'assembly':
            search_paths = [
                file_path,  # Direct path from registry
                os.path.join('cli', 'extensions', 'assemblies', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
                os.path.join(os.getcwd(), file_path),
                os.path.join(os.getcwd(), os.path.basename(file_path))
            ]
        elif extension_info['type'] == 'pe':
            search_paths = [
                file_path,  # Direct path from registry
                os.path.join('cli', 'extensions', 'pe', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
                os.path.join(os.getcwd(), file_path),
                os.path.join(os.getcwd(), os.path.basename(file_path))
            ]
        else:
            return None

        # Find the actual file
        actual_file_path = None
        for path in search_paths:
            if os.path.exists(path):
                actual_file_path = path
                break

        if not actual_file_path:
            print(f"{red('[-]')} Extension file not found: {file_path}")
            return None

        # Read file content and encode it
        try:
            with open(actual_file_path, 'rb') as f:
                file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode('utf-8')
        except Exception as e:
            print(f"{red('[-]')} Error reading file {actual_file_path}: {str(e)}")
            return None

        # Build the appropriate execute command with encoded content
        if extension_info['type'] == 'bof':
            execute_cmd = f"execute-bof {encoded_content}"
        elif extension_info['type'] == 'assembly':
            execute_cmd = f"execute-assembly {encoded_content}"
        elif extension_info['type'] == 'pe':
            execute_cmd = f"execute-pe {encoded_content}"
        else:
            return None

        # Add any additional arguments from the original command
        if len(command_parts) > 1:
            execute_cmd += " " + " ".join(command_parts[1:])

        return execute_cmd
    
    def get_available_commands(self):
        return list(self.command_registry.keys())
    
    def get_command_info(self, command_name):
        return self.command_registry.get(command_name.lower())
    
    def print_available_commands(self):
        if not self.command_registry:
            print("[*] No extension commands available")
            return

        print("Available Extension Commands:")
        print("-" * 60)
        print(f"{'Command':<20} {'Type':<10} {'File':<25}")
        print("-" * 60)

        for cmd_name, info in sorted(self.command_registry.items()):
            print(f"{cmd_name:<20} {info['type']:<10} {info['original_name']:<25}")

        print("-" * 60)
        print(f"Total: {len(self.command_registry)} extension commands")

    def print_extension_list(self):
        if not self.command_registry:
            print("[*] No extension commands available")
            return

        print("Available Extension Commands:")
        print("-" * 80)
        print(f"{'Command':<20} {'Type':<10} {'File':<25} {'Description':<20}")
        print("-" * 80)

        for cmd_name, info in sorted(self.command_registry.items()):
            description = info['metadata'].get('help', 'No description') if info['metadata'] else 'No description'
            print(f"{cmd_name:<20} {info['type']:<10} {info['original_name']:<25} {description:<20}")

        print("-" * 80)
        print(f"Total: {len(self.command_registry)} extension commands")

    def print_extension_info(self, command_name):
        if not command_name:
            print(f"{red('[-]')} No command name provided. Usage: extender info <command_name>")
            return

        command_name_lower = command_name.lower()
        if command_name_lower not in self.command_registry:
            print(f"{red('[-]')} Extension '{command_name}' not found")
            return

        info = self.command_registry[command_name_lower]
        metadata = info['metadata']

        print(f"\n{bright('Extension Information')}")
        print("=" * 50)
        print(f"Command:     {command_name_lower}")
        print(f"Type:        {info['type'].upper()}")
        print(f"Name:        {command_name_lower}")

        if metadata:
            print(f"Version:     {metadata.get('version', 'N/A')}")
            print(f"Author:      {metadata.get('extension_author', metadata.get('original_author', 'N/A'))}")
            print(f"Repository:  {metadata.get('repo_url', 'N/A')}")
            print(f"Help:        {metadata.get('help', 'N/A')}")
            print(f"Usage:       {metadata.get('usage', 'N/A')}")
        else:
            print(f"Version:     N/A")
            print(f"Author:      N/A")
            print(f"Repository:  N/A")
            print(f"Help:        N/A")
            print(f"Usage:       N/A")

        print("=" * 50)
