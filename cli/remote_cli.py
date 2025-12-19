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
            'exit', 'quit', 'clear', 'status', 'task', 'result', 'save', 'addtask',
            'harvest', 'execute-bof', 'execute-assembly'
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
            if len(command_parts) >= 3 and command_parts[0].lower() == 'profile' and command_parts[1].lower() == 'add':
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
        """Start a thread to periodically refresh agent status"""
        self.agent_refresh_stop_event.clear()
        self.agent_refresh_thread = threading.Thread(target=self._agent_refresh_worker)
        self.agent_refresh_thread.daemon = True
        self.agent_refresh_thread.start()

    def _stop_agent_refresh_thread(self):
        """Stop the agent refresh thread"""
        if self.agent_refresh_stop_event:
            self.agent_refresh_stop_event.set()
        if self.agent_refresh_thread and self.agent_refresh_thread.is_alive():
            self.agent_refresh_thread.join(timeout=1)

    def _process_agent_update_queue(self):
        """Process any queued agent updates and display alerts for new agents"""
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
        """Handle agent update messages and display alerts"""
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
