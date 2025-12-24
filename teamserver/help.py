def get_help_display():
    return """
Available NeoC2 Terminal Commands:
════════════════════════════════════════════════════════════════

INFRASTRUCTURE MANAGEMENT:
  listener    - Manage listeners (create, start, stop, delete)
  profile     - Communication profile management (list, add, reload)
  failover    - Manage failover deployment
  stager      - Generate stagers
  payload     - Generate various payload types
  payload_upload - Upload staging payload to C2 endpoint

AGENT MANAGEMENT:
  agent       - Manage agents (list, interact, info, kill)
  beacon      - Active HTTP/S Agents
  interact    - Enter Interactive mode with a beacon
  interactive - Check if session is in interactive mode
  sleep       - Change agent sleep interval

MODULES & EXECUTION:
  modules     - Manage modules (list, load, info, check)
  run         - Execute modules
  task        - Pending agent tasks
  result      - View task results
  taskchain   - Task Orchestration
  cmd         - Execute shell command using interactive api (in interactive mode)
  addcmd      - Execute shell command using queued api

OPERATIONS & TACTICS:
  upload      - Upload files to agents
  download    - Download files from agents/C2 server
  reverse_proxy - Start server-side reverse proxy 
  reverse_proxy_start - Make agent connect to server proxy
  socks       - Start a local socks5 proxy chain
  persist     - Persist an executable or script
  execute-bof - Load and execute bofs on agent session
  execute-assembly - Load and execute .NET assemblies in-memory on agents
  peinject    - Injects unmanaged PE by Process Hollowing into svchost.exe
  pinject     - Injects shellcode into notepad.exe or explorer.exe 
  pwsh        - Execute powershell script on agent session
  tty_shell   - Start tty shell

ENCRYPTION & SECURITY:
  encryption  - Encryption operations

REPORTING & LOGGING:
  save        - Save specific results to logs directory
  reporting   - Generate reports
  event       - View Event monitor

FRAMEWORK UTILITIES:
  status      - Show framework status
  clear       - Clear terminal
  back        - Exit interactive mode

NOTES:
  • Parameters in < > are required
  • Parameters in [ ] are optional
  • Some commands may require additional privileges
  • Use 'cmd <command>' in interactive mode to execute direct agent commands

Use 'help' to show this message again.
    """



#========== OTHER DISPLAY=============



def get_listener_help_display():
    return """
Available Listener Commands:
════════════════════════════════════════════════════════════════

COMMANDS:
  • listener list                     List listeners
  • listener create <name> <type> <port> <ip> <profile_name=>   Create listeners
  • listener start <name>             Start a listener
  • listener stop <name>              Stop an active listener
  • listener delete <name>            Delete a stopped listener

EXAMPLES:
  • listener create myhttps https 443 127.0.0.1 profile_name=my_htttps_profile
  • listener start myhttps

TIPS:
  • Use 'listener list' to see existing listeners
  • Ensure ports are not already in use
    """


def get_agent_help_display():
    return """
Available Agent Commands:
═══════════════════════════════════════════════════════════════════

SYNTAX:
  • agent <list|interact|info|kill> [options]

COMMANDS:
  • agent list                    List agents
  • agent interact <id>           Interact with an active agent
  • agent info <id>               Show agent information
  • agent kill <id>               Kill an agent

TIPS:
  • Use 'agent list' to see available agents
  • Interact with an agent before executing commands
  • Use 'interact <id>' for direct interaction
    """


def get_modules_help_display():
    return """
Available Modules Commands:
═══════════════════════════════════════════════════════════════════

SYNTAX:
  • modules <list|load|info|reload|check> [module_name]

COMMANDS:
  • modules list                    List all modules
  • modules load <module_name>      Load module into memory
  • modules info <module_name>      Display module details
  • modules reload <module_name>    Reload module
  • modules check <module_name>     Check module compatibility

TIPS:
  • Use 'modules list' to see available modules
  • Use 'modules info <name>' to see required parameters
  • Use 'modules help' for detailed command usage
    """


def get_run_help_display():
    return """
Available Run Command Options:
═══════════════════════════════════════════════════════════════════

SYNTAX:
  • run <module_name> [option1=value1 option2=value2 ...]

EXAMPLES:
  • run screenshot agent_id=agent-001
  • run keylogger duration=300
  • (In interactive mode) run screenshot

TIPS:
  • Use 'modules list' to see all available modules
  • Use 'modules info <module_name>' to see required parameters
  • Use 'run help' for detailed command usage
  • Module parameters vary by module type
    """




def get_encryption_help():
    return """
ENCRYPTION & STEGANOGRAPHY - Command Reference
═════════════════════════════════════════════════════════════════════════════

COMMANDS:

  encryption encrypt <algorithm> <data> [options]
      Encrypt data using specified algorithm
      Algorithms: fernet, aes, rsa, xor

  encryption decrypt <algorithm> <encrypted_data> [options]
      Decrypt data using specified algorithm

  encryption keygen <algorithm> [options]
      Generate encryption keys
      Algorithms: fernet, aes, rsa, xor

  encryption stego hide <image> <data> <output> [key=<key>]
      Hide data in an image using steganography

  encryption stego extract <image> [key=<key>]
      Extract hidden data from an image

  encryption hmac generate <data> [key=<key>]
      Generate HMAC signature for data

  encryption hmac verify <data> <hmac> [key=<key>]
      Verify HMAC signature

  encryption list
      List available encryption capabilities

  encryption help
      Show this help message

EXAMPLES:

  # Encrypt with Fernet (simple & secure)
  encryption encrypt fernet "Hello World"

  # Encrypt with AES using password
  encryption encrypt aes "Secret Data" password=mypass123

  # Generate RSA key pair
  encryption keygen rsa output=mykeys

  # Hide message in image
  encryption stego hide photo.png "Secret" stego.png

  # Generate and verify HMAC
  encryption hmac generate "Important Data" key=deadbeef

TIPS:
  • Use 'encryption list' to see available algorithms
  • For more details on a specific command, use: encryption <command>
  • Base64 encoding is used automatically for binary data
    """


def get_listener_usage():
    return "USAGE: listener <action> <listener_name> [options]"


def get_modules_load_usage():
    return "Usage: modules load <module_path>"


def get_modules_check_usage():
    return "Usage: modules check <module_path>"


def get_pinject_usage():
    return "USAGE: pinject <shellcode_file> [agent_id=<agent_id>]"


def get_pwsh_usage():
    return "USAGE: pwsh <script_file> [agent_id=<agent_id>] [arguments=<script_arguments>]"


def get_execute_bof_usage():
    return "USAGE: execute-bof <bof_file> [arguments] [agent_id=<agent_id>]"


def get_execute_assembly_usage():
    return "USAGE: execute-assembly <assembly_file> [agent_id=<agent_id>]"


def get_persist_usage():
    return "USAGE: persist <method> <payload_path> [agent_id=<agent_id>] [name=<persistence_name>] [interval=<minutes>]"


def get_peinject_usage():
    return "USAGE: peinject <pe_file> [agent_id=<agent_id>]"


def get_agent_interact_usage():
    return "Usage: agent interact <agent_id>"


def get_agent_execute_usage():
    return "Usage: agent execute <command>"


def get_agent_info_usage():
    return "Usage: agent info <agent_id>"


def get_agent_kill_usage():
    return "Usage: agent kill <agent_id>"


def get_agent_monitor_usage():
    return "Usage: agent monitor <agent_id>"


def get_agent_unmonitor_usage():
    return "Usage: agent unmonitor <agent_id>"


def get_encryption_stego_hide_usage():
    return "Usage: encryption stego hide <image_path> <data> <output_path> [key=<key>]"


def get_encryption_stego_extract_usage():
    return "Usage: encryption stego extract <image_path> [key=<key>]"


def get_encryption_hmac_generate_usage():
    return "Usage: encryption hmac generate <data> [key=<key>]"


def get_encryption_hmac_verify_usage():
    return "Usage: encryption hmac verify <data> <hmac> [key=<key>]"


def get_download_usage():
    return "Usage: download <agent_id> <remote_file_path> (for agent downloads) OR download <server_file_path> (for server downloads)"


def get_upload_usage():
    return "Usage: upload <agent_id> <local_file_path> <remote_file_path> OR upload <local_file_path> <remote_file_path> (in interactive mode)"


def get_profile_add_usage():
    return "Usage: profile add <path_to_json> OR profile add base64:<base64_encoded_json>"


def get_profile_reload_usage():
    return "USAGE: profile reload <profile_path> <profile_name>"


def get_payload_upload_usage():
    return "Usage: payload_upload upload <local_file_path>"


def get_taskchain_create_usage():
    return "Usage: taskchain create <agent_id> <module1=arg1,arg2,module2=arg3,module3> [name=chain_name] [execute=true] OR taskchain create <module1=arg1,arg2,module2=arg3,module3> (in interactive mode)"


def get_taskchain_status_usage():
    return "Usage: taskchain status <chain_id>"


def get_taskchain_execute_usage():
    return "Usage: taskchain execute <chain_id>"


def get_reporting_export_usage():
    return "Usage: reporting export <report_type> <format> [options]"


def get_task_usage():
    return "Usage: task <agent_id> OR task (in interactive mode)"


def get_result_usage():
    return "Usage: result <agent_id> OR result list OR result <task_id>"


def get_addcmd_usage():
    return "USAGE: addcmd <agent_id> <command> OR addcmd <command> (in interactive mode)\n\nNote: Uses the standard queued API for command execution."


def get_save_usage():
    return "Usage: save <task_id>"


def get_interact_usage():
    return "Usage: interact <agent_id>"


def get_cmd_usage():
    return "Usage: cmd <command> (in interactive mode)"


def get_event_search_usage():
    return "Usage: event search <query>"


def get_reverse_proxy_usage():
    return "Usage: reverse_proxy <start|stop> [agent_id] [port]"


def get_cli_socks_proxy_usage():
    return "Usage: cli_socks_proxy <start|stop> [agent_id] [port]"


def get_failover_import_keys_usage():
    return "Usage: failover import-keys <file_path>"


def get_failover_export_keys_usage():
    return "Usage: failover export-keys <file_path> [agent_id]"


def get_failover_unknown_action_usage():
    return "Unknown failover action. Use: import-keys, export-keys"


def get_failover_help():
    return """
FAILOVER COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • failover import-keys <file_path>          - Import agent keys from distribution file
  • failover export-keys <file_path> [agent_id] - Export agent keys to distribution file

DESCRIPTION:
  Import and export agent secret keys for failover C2 server setup.
  This allows agents to communicate with backup/secondary C2 servers.

EXAMPLES:
  • failover export-keys /tmp/agent_keys.json
  • failover export-keys /tmp/single_agent.json AGENT123
  • failover import-keys /tmp/agent_keys.json
                    """


def get_task_pending_usage():
    return "Usage: task <agent_id> pending tasks would be shown here"


def get_result_list_usage():
    return "Usage: result <agent_id> OR result list OR result <task_id>"


def get_addcmd_agent_usage():
    return "Usage: addcmd <agent_id> <command>"


def get_save_task_id_usage():
    return "Usage: save <task_id>"


def get_interact_agent_id_usage():
    return "Usage: interact <agent_id>"
