def get_help_display():
    return """
Available NeoC2 Terminal Commands:
════════════════════════════════════════════════════════════════

INFRASTRUCTURE MANAGEMENT:
  listener    - Manage listeners (create, start, stop, delete)
  profile     - Communication profile management (list, add, reload)
  stager      - Generate stagers
  payload     - Generate various payload types
  payload_upload - Upload staging payload to C2 endpoint

AGENT MANAGEMENT:
  agent       - Manage agents (list, interact, info, kill)
  beacon      - Active HTTP/S Agents
  interact    - Eneter Interactive mode with a beacon
  interactive - Check if session is in interactive mode
  sleep       - Change agent sleep interval

MODULES & EXECUTION:
  modules     - Manage modules (list, load, info, check)
  run         - Execute modules
  task        - Pending agent tasks
  addtask     - Add a queued task to an agent directly
  result      - View task results
  taskchain   - Task Orchestration

OPERATIONS & TACTICS:
  evasion     - Basic AMSI/ETW bypass
  upload      - Upload files to agents
  download    - Download files from agents/C2 server
  persist     - Persist an executable or script
  inline-execute - Execute bofs on agent session
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
  history     - Show command history
  clear       - Clear terminal
  back        - Exit interactive mode

NOTES:
  • Parameters in < > are required
  • Parameters in [ ] are optional
  • Some commands may require additional privileges

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


def get_evasion_help_display():
    return """
Available Evasion Commands:
══════════════════════════════════════════════════════════════════════

SYNTAX:
  • evasion <enable|disable> <technique>

EXAMPLES:
  • evasion enable amsi_bypass
  • evasion disable etw_bypass

TECHNIQUES:
  • amsi_bypass, etw_bypass

TIP:
  • Execute from within agent interactive session
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
