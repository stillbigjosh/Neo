# Creating a Custom Module

NeoC2 is a highly customizable framework. To create a custom module, the following are required by the Framework:

1. **Python wrapper modules**: Python file that interface with the framework's Agent Manager and external module or builtin module of the agent
2. **External modules(optional)**: The external module located in the `modules/external/` directory to be executed on the agent
   
Every Python wrapper modules must be a Python file that implements two required functions:

### 1. `get_info()` function

This function returns metadata about the module:

```
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

```
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


## Module Compatibility

To verify if a custom module is compatible with the framework. From the remote client run:

```
NeoC2 (user@remote) > modules check <module_path_on_server>

# Example:
NeoC2 (user@remote) > modules check modules/donut.py
```

## Module Execution

To run the Custom module that passed basic compatibility check. Use the `run` base-command:

```
NeoC2 (user@remote) > run <module_name> <agent_id> [options]
```


## Module Registration

Modules are automatically loaded when:
1. The module file is placed in the `modules/` directory
2. The module file has a `.py` extension
3. The module implements both `get_info()` and `execute()` functions
4. The module passes compatibility checks






    










