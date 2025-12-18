import os
import base64
from pathlib import Path

def get_info():
    return {
        "name": "execute-bof",
        "description": "Load and execute Beacon Object Files (BOFs) in-memory using the embedded COFF loader on agents",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework by @stillbigjosh",
        "references": [
            "https://www.cobaltstrike.com/help-beacon-object-files",
            "https://docs.cobaltstrike.com/help-beacon-object-files"
        ],
        "technique_id": "T1055,T1620",
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the BOF on",
                "required": True
            },
            "bof_path": {
                "description": "Path to the Beacon Object File (BOF) relative to modules/external/bof/",
                "required": True
            },
            "arguments": {
                "description": "Arguments to the BOF",
                "required": False,
                "default": ""
            }
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    bof_path = options.get("bof_path")
    arguments = options.get("arguments", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not bof_path:
        return {
            "success": False,
            "error": "bof_path is required"
        }
    
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    try:
        agent_manager = session.agent_manager

        agent = agent_manager.get_agent(agent_id)
        if not agent:
            return {
                "success": False,
                "error": f"Agent {agent_id} not found"
            }

        if os.path.isabs(bof_path) and os.path.exists(bof_path):
            bof_full_path = bof_path
        else:
            bof_full_path = os.path.join(os.path.dirname(__file__), 'external', 'bof', bof_path)

            if not os.path.exists(bof_full_path):
                possible_paths = [
                    os.path.join(os.path.dirname(__file__), 'external', 'bof', bof_path),  # Default location
                    bof_path,  # Direct relative path
                    os.path.join('modules', 'external', 'bof', os.path.basename(bof_path)),  # Just filename in default
                    os.path.join('/opt/modules/external/bof', os.path.basename(bof_path)),  # /opt location
                    os.path.join('/opt/neoc2/modules/external/bof', os.path.basename(bof_path)),  # /opt/neoc2 location
                ]

                found = False
                for path in possible_paths:
                    if os.path.exists(path):
                        bof_full_path = path
                        found = True
                        break

                if not found:
                    bof_dir = os.path.join(os.path.dirname(__file__), 'external', 'bof')
                    available_files = []
                    if os.path.exists(bof_dir):
                        available_files = [f for f in os.listdir(bof_dir) if os.path.isfile(os.path.join(bof_dir, f))]

                    return {
                        "success": False,
                        "error": f"BOF file does not exist: {bof_path}. Searched in default locations. Available BOF files in modules/external/bof/: {available_files if available_files else ['No files found']}"
                    }

        with open(bof_full_path, 'rb') as f:
            bof_content = f.read()

        encoded_bof = base64.b64encode(bof_content).decode('utf-8')

        if arguments:
            bof_command = f"bof {encoded_bof} {arguments}"
        else:
            bof_command = f"bof {encoded_bof}"

        # Validate that the BOF is a valid COFF file before sending
        # Check for COFF signature at the beginning of the file
        if len(bof_content) < 4:
            return {
                "success": False,
                "error": f"BOF file {bof_path} is too small to be a valid COFF file"
            }

        magic_bytes = bof_content[:4]

        # Check if this is being executed in interactive mode
        if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
            # Return the command that should be executed interactively
            result = {
                "success": True,
                "output": f"[x] BOF execution prepared for interactive mode",
                "command": bof_command,
                "bof_path": bof_full_path,
                "encoded_bof_size": len(encoded_bof)
            }

            session.audit_logger = getattr(session, 'audit_logger', None)
            if session.audit_logger:
                session.audit_logger.log_event(
                    user_id=getattr(session, 'user_id', 'unknown'),
                    action='bof_execute',
                    resource_type='task',
                    resource_id='interactive',
                    details=f"BOF execution prepared for interactive mode. Command: bof <base64_data> ({len(encoded_bof)} chars encoded)",
                    ip_address='127.0.0.1'
                )

            return result
        else:
            task_id = agent_manager.add_task(agent_id, bof_command)
            if task_id:
                result = {
                    "success": True,
                    "output": f"[x] BOF execution task queued for agent {agent_id}",
                    "task_id": task_id,
                    "bof_command": bof_command,
                    "bof_path": bof_full_path,
                    "encoded_bof_size": len(encoded_bof)
                }

                session.audit_logger = getattr(session, 'audit_logger', None)
                if session.audit_logger:
                    session.audit_logger.log_event(
                        user_id=getattr(session, 'user_id', 'unknown'),
                        action='bof_execute',
                        resource_type='task',
                        resource_id=task_id,
                        details=f"BOF execution queued for agent {agent_id}. Command: bof <base64_data> ({len(encoded_bof)} chars encoded)",
                        ip_address='127.0.0.1'
                    )

                return result
            else:
                return {
                    "success": False,
                    "error": f"Failed to queue BOF execution task for agent {agent_id}"
                }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing BOF: {str(e)}"
        }


def _handle_coff_command(command_parts, session):
    try:
        if len(command_parts) < 3:
            return "Usage: coff <agent_id> <bof_path> [arguments]", 'error'
        
        agent_id = command_parts[1]
        bof_path = command_parts[2]
        
        # Check if agent exists
        agent_manager = session.agent_manager
        if not agent_manager:
            return "Agent manager not initialized", 'error'
        
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            return f"Agent {agent_id} not found", 'error'
        
        # Arguments are everything after the BOF path
        arguments = []
        if len(command_parts) > 3:
            arguments = command_parts[3:]
        
        # Prepare options for the coff module
        options = {
            'agent_id': agent_id,
            'bof_path': bof_path,
            'arguments': ' '.join(arguments) if arguments else ''
        }
        
        # Use the module manager to execute the coff module
        module_manager = session.module_manager
        if not module_manager:
            return "Module manager not initialized", 'error'
        
        # Check if coff module is already loaded to avoid reload failure
        loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})
        
        # Try to get coff module - it might already be loaded
        coff_module = None
        if 'coff' in loaded_modules_dict:
            coff_module = loaded_modules_dict['coff']['module']
        else:
            # Attempt to load the coff module (this might fail if already loaded)
            module_path = os.path.join('modules', 'coff.py')
            load_success = module_manager.load_module(module_path)
            if load_success or 'coff' in loaded_modules_dict:
                # Check again after attempted load
                if 'coff' in loaded_modules_dict:
                    coff_module = loaded_modules_dict['coff']['module']
        
        if coff_module and hasattr(coff_module, 'execute'):
            result = coff_module.execute(options, session)
            if 'success' in result and result['success']:
                return result.get('output', 'BOF execution task queued successfully'), 'success'
            else:
                return result.get('error', 'Unknown error occurred during BOF execution'), 'error'
        else:
            return "Could not load COFF module from modules/coff.py", 'error'
    
    except Exception as e:
        return f"Error handling COFF command: {str(e)}", 'error'
