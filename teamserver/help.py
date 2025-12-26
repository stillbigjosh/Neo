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
  beacon      - HTTP/S Agents(agent list)
  upload      - Upload files to agents
  sleep       - Change agent sleep interval
  interact    - Enter Interactive mode with a beacon
  download    - Download files from agents
  tty_shell   - Start tty shell
  interactive - Check if session is in interactive mode
  reverse_proxy_start - Start agent connection to server proxy
  reverse_proxy_stop - Stop agent connection to server proxy

MODULES & EXECUTION:
  modules     - Manage modules (list, load, info, check)
  run         - Execute modules
  task        - Pending agent tasks
  result      - View task results
  taskchain   - Task Orchestration
  cmd         - Execute shell command using interactive api (in interactive mode)
  addcmd      - Execute shell command using queued api

OPERATIONS & TACTICS:
  reverse_proxy - Start server-side reverse proxy 
  pwsh        - Execute powershell script on agent session
  persist     - Persist an executable or script
  execute-bof - Load and execute bofs on agent session
  execute-assembly - Load and execute .NET assemblies in-memory on agent session
  peinject    - Unmanaged PE injection into svchost.exe (Process Hollowing)
  pinject     - Shellcode injection into available stable process (NtQueueApcThread)

CLIENT:
  download    - Download logs from C2 server
  extenders   - List available extensions (BOFs & Assemblies)
  socks       - Start a local socks5 proxy chain

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
  • modules <list|load|info|check> [module_name]

COMMANDS:
  • modules list                    List all modules
  • modules load <module_name>      Load module into memory
  • modules info <module_name>      Display module details
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


def get_payload_upload_help_display():
    return """
PAYLOAD UPLOAD COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • payload_upload upload <file> [uri=<custom_uri>] - Upload a payload file for stagers
  • payload_upload status                          - Check status of uploaded payload
  • payload_upload clear                           - Clear the currently uploaded payload

DESCRIPTION:
  Upload custom payloads (executables, scripts, etc.) to be used with stagers.
  Optionally specify a custom URI where the payload will be available.
  Supported extensions: .exe, .dll, .py, .js, .vbs, .bat, .ps1, .bin, .dat, .raw

EXAMPLES:
  • payload_upload upload /tmp/myscript.exe                    # Upload with default URI
  • payload_upload upload /tmp/myscript.exe uri=custom_payload # Upload with custom URI
  • payload_upload status
  • payload_upload clear
    """


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


def get_payload_help_display():
    return """
PAYLOAD GENERATION COMMANDS
═══════════════════════════════════════════════════════════════════

SYNTAX:
  • payload <type> <listener_name> [options]

AVAILABLE PAYLOAD TYPES:
  • morpheus             - Lightweight Python agent (cross platform)
  • trinity              - Advanced Go agent compiled to Windows executable

OPTIONS:
  • --obfuscate          - Enable string obfuscation
  • --disable-sandbox    - Disable sandbox/antidebugging checks
  • --output <filename>  - Save payload to file (optional)
  • --linux              - Compile payload to Linux binary
  • --windows            - Compile payload to Windows binary
  • --redirector         - Use redirector host and port from profile instead of C2 URL
  • --use-failover       - Embed failover C2 URLs from profile into agent
  • --no-bof             - Exclude Beacon Object File (BOF) execution capability
  • --no-assembly        - Exclude .NET assembly execution capability
  • --no-pe              - Exclude PE injection capability
  • --no-shellcode       - Exclude shellcode injection capability
  • --no-reverse-proxy   - Exclude reverse proxy (SOCKS5) capability
  • --no-sandbox         - Exclude sandbox detection capability

EXAMPLES:
  • payload morpheus <listener_name> [--obfuscate] [--disable-sandbox] [--linux] [--redirector] [--use-failover]
  • payload trinity <listener_name> [--obfuscate] [--disable-sandbox] [--windows] [--redirector] [--use-failover] [--no-bof] [--no-assembly] [--no-pe] [--no-shellcode] [--no-reverse-proxy] [--no-sandbox]
    """


def get_encryption_encrypt_usage():
    return """
    USAGE:
        encryption encrypt <algorithm> <data> [options]

    ALGORITHMS:
        fernet    - Symmetric encryption (default)
        aes       - AES encryption (requires password=<pwd>)
        rsa       - RSA encryption (requires public_key=<path>)
        xor       - XOR encryption (requires key=<key>)

    OPTIONS:
        password=<pwd>      - Password for AES
        public_key=<path>   - Path to RSA public key file
        key=<key>           - Key for XOR (hex string)
        output=<path>       - Save encrypted data to file

    EXAMPLES:
        encryption encrypt fernet "Hello World"
        encryption encrypt aes "Secret Data" password=mypass123
        encryption encrypt xor "Data" key=deadbeef output=out.enc
    """


def get_encryption_decrypt_usage():
    return """
    USAGE:
        encryption decrypt <algorithm> <encrypted_data> [options]

    ALGORITHMS:
        fernet    - Symmetric decryption
        aes       - AES decryption (requires password=<pwd> salt=<salt>)
        rsa       - RSA decryption (requires private_key=<path>)
        xor       - XOR decryption (requires key=<key>)

    OPTIONS:
        password=<pwd>      - Password for AES
        salt=<salt>         - Salt for AES (base64)
        private_key=<path>  - Path to RSA private key file
        key=<key>           - Key for XOR (hex string)
        input=<path>        - Read encrypted data from file

    EXAMPLES:
        encryption decrypt fernet <base64_data>
        encryption decrypt aes <data> password=mypass123 salt=<salt>
        encryption decrypt xor <data> key=deadbeef
    """


def get_encryption_keygen_usage():
    return """
    USAGE:
        encryption keygen <algorithm> [options]

    ALGORITHMS:
        fernet    - Generate Fernet key
        aes       - Generate AES key (requires password=<pwd>)
        rsa       - Generate RSA key pair
        xor       - Generate XOR key (optional: length=<bytes>)

    OPTIONS:
        password=<pwd>      - Password for AES key derivation
        length=<bytes>      - Length for XOR key (default: 32)
        output=<prefix>     - Output prefix for key files

    EXAMPLES:
        encryption keygen rsa output=my_rsa
        encryption keygen xor length=64
        encryption keygen aes password=mypass123
    """


def get_profile_help_display():
    return """
PROFILE MANAGEMENT COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • profile add <path>                - Add a new communication profile from a JSON file
  • profile add base64:<encoded_json> - Add a new communication profile from base64 encoded JSON
  • profile list                      - List all communication profiles in the database
  • profile reload <path> <name>      - Reload an existing profile with changes from a JSON file

EXAMPLES:
  • profile add /path/to/profile.json
  • profile add base64:eyJuYW1lIjoiTXlQcm9maWxlIiwiY29uZmlnIjp7fX0=
  • profile reload /path/to/updated.json MyProfile
"""


def get_taskchain_help_display():
    return """
TASK CHAIN COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • taskchain create <agent_id> <module1=args1,module2=args2,module3=args3> [name=chain_name] [execute=true]
  • taskchain list [agent_id=<agent_id>] [status=<status>] [limit=<limit>]
  • taskchain status <chain_id>
  • taskchain execute <chain_id>
  • taskchain help

OPTIONS:
  • name=chain_name    - Name for the task chain
  • execute=true       - Execute the chain immediately after creation (default: false)
  • agent_id=agent_id  - Filter chains by agent ID (for list command)
  • status=status      - Filter chains by status (for list command)
  • limit=limit        - Limit number of results (for list command)

EXAMPLES:
  • taskchain create AGENT001 get_system,whoami,pslist name=priv_escalation
  • taskchain list
  • taskchain list agent_id=AGENT001 status=pending
  • taskchain status CHAIN123
  • taskchain execute CHAIN123
"""


def get_reporting_help_display():
    return """
REPORTING COMMANDS
═══════════════════════════════════════════════════════════════════

COMMANDS:
  • reporting list
  • reporting <report_type> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  • reporting export <report_type> <format> [start_date=YYYY-MM-DD] [end_date=YYYY-MM-DD] [agent_id=AGENT_ID] [user_id=USER_ID]
  • reporting help

REPORT TYPES:
  • agent_activity    - Agent activity and communication report
  • task_execution    - Task execution and results report
  • audit_log         - Security audit log with user actions
  • module_usage      - Module usage and execution patterns
  • system_overview   - System health and configuration report

EXPORT FORMATS:
  • csv, json

EXAMPLES:
  • reporting list
  • reporting agent_activity
  • reporting task_execution start_date=2024-01-01 end_date=2024-12-31
  • reporting audit_log agent_id=AGENT001
  • reporting export module_usage csv
  • reporting export task_execution json start_date=2024-01-01
"""


def get_modules_info_usage():
    return """USAGE:
                modules info <module_name>"""


def get_encryption_stego_usage():
    return """
    USAGE:
        encryption stego hide <image_path> <data> <output_path> [key=<key>]
        encryption stego extract <image_path> [key=<key>]

    DESCRIPTION:
        Hide or extract data from images using LSB steganography

    EXAMPLES:
        encryption stego hide image.png "Secret Message" stego_image.png
        encryption stego extract stego_image.png
    """


def get_encryption_hmac_usage():
    return """
    USAGE:
        encryption hmac generate <data> [key=<key>]
        encryption hmac verify <data> <hmac> [key=<key>]

    DESCRIPTION:
        Generate or verify HMAC signatures

    EXAMPLES:
        encryption hmac generate "Important Data" key=deadbeef
        encryption hmac verify "Important Data" <hmac_hex> key=deadbeef
    """


def get_encryption_list_display():
    return """
Available Encryption Capabilities:
═══════════════════════════════════════════════════════════════════

SYMMETRIC ENCRYPTION:
  • Fernet      - High-level symmetric encryption (recommended)
  • AES         - Advanced Encryption Standard (password-based)
  • XOR         - Simple XOR cipher (fast, low security)

ASYMMETRIC ENCRYPTION:
  • RSA         - Public-key cryptography (2048-bit)

STEGANOGRAPHY:
  • LSB         - Least Significant Bit image steganography

MESSAGE AUTHENTICATION:
  • HMAC        - Hash-based Message Authentication Code (SHA-256)

KEY GENERATION:
  • Fernet keys
  • AES keys (password-derived with PBKDF2)
  • RSA key pairs (2048-bit)
  • XOR keys (custom length)
  • Steganography keys

Use 'encryption help' for detailed command usage.
    """


def get_addcmd_usage_detailed():
    return "USAGE: addcmd <agent_id> <command> OR addcmd <command> (in interactive mode)\n\nNote: Uses the standard queued API for command execution."
