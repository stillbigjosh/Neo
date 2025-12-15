def get_help_display():
    return """
Available NeoC2 Terminal Commands:
════════════════════════════════════════════════════════════════

Framework:
  listener    - Manage listeners (create, start, stop, delete)
  modules     - Manage modules (list, load, info, check)
  run         - Execute modules
  stager      - Generate stagers
  beacon      - Active HTTP/S Agents
  agent       - Manage agents (list, interact, info, kill)
  task        - Pending agent tasks
  addtask     - Add a task to an agent directly
  result      - View task results
  interact    - Interact with a beacon
  interactive - Check if session is in interactive mode
  save        - Save specific results to logs directory
  payload_upload - Upload staging payload to C2 endpoint
  encryption  - Encryption operations
  profile     - Communication profile management (list, add, reload)
  payload     - Generate various payload types
  taskchain   - Task Orchestration
  reporting   - Generate reports
  event       - View Event monitor
  status      - Show framework status
  history     - Show command history
  clear       - Clear terminal
  back	      - Exit interactive mode
  
Operations:
  evasion     - AMSI/ETW bypass
  upload      - Upload files to agents
  download    - Download files from agents/C2 server
  persist     - Persist an executable or script
  inline-execute - Execute bofs on agent session
  peinject    - Injects PE files by Process Hollowing into svchost.exe
  pinject     - Injects shellcode into notepad.exe or explorer.exe
  pwsh        - Execute powershell script on agent session
  sleep       - Change agent sleep interval
  tty_shell   - Start tty shell

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
  • listener list              List listeners
  • listener create <name> <type> <port> Create listeners
    listener create myhttp http 443
  • listener start <name>      Start a listener
  • listener stop <name>       Stop an active listener
  • listener delete <name>     Delete a stopped listenr
    """


def get_agent_help_display():
    return """
Available Agent Commands:
════════════════════════════════════════════════════════

SYNTAX:
  • agent <list|interact|info|kill> [options]

COMMANDS:
  • agent list            List agents
  • agent interact <id>   Interact with an active agent
  • agent info <id>       Show an agent info
  • agent kill <id>       Kill an agent

TIPS:
  • Interact before executing
    """


def get_modules_help_display():
    return """
Available Modules Commands:
═══════════════════════════════════════════════════════

SYNTAX:
  • modules <list|load|info|reload> [module_name]

COMMANDS:
  • modules list           List all modules
  • modules load <n>       Load module into memory
  • modules info <n>       Display module details
  • modules reload <n>     Reload module
  • modules check <n>      Check a module compatibility

TIP:
  • Use 'modules list' to see available modules

Use 'modules help' for detailed command usage.
    """


def get_run_help_display():
    return """
Available Run Command Options:
══════════════════════════════════════════════════

SYNTAX:
  • run <module> [option1=value1 option2=value2]

EXAMPLE:
  • run screenshot agent_id=agent-001 <options>
EXAMPLE: (Interactive mode)
  • run screenshot <options>

TIPS:
  • Use 'modules list' to see all modules
  • Use 'modules info <n>' for parameters

Use 'run help' for detailed command usage.
    """


def get_stager_help_display():
    return """
Available Stager Commands:
════════════════════════════════════════════════════

SYNTAX:
  • stager <generate|list> <type> [options]

COMMANDS:
  • stager list              List all stagers
  • stager generate <type>   Generate new interactive stager

EXAMPLES:
  • stager list
  • stager generate python host= port= protocol=
  • stager generate bash host= port= protocol=

TYPES:
  • python, bash, powershell

Use 'stager help' for detailed command usage.
    """


def get_evasion_help_display():
    return """
Available Evasion Commands:
══════════════════════════════════════════════════════════════════════

SYNTAX:
  • evasion <enable|disable> <type> [options]

COMMANDS:
  • evasion enable <type>     Enable technique on current agent
  • evasion disable <type>    Disable technique on current agent

EXAMPLES:
  • evasion enable amsi_bypass
  • evasion disable amsi_bypass

TYPES:
  • amsi_bypass, etw_bypass

Use 'evasion help' for detailed command usage.
    """



def get_encryption_help():
    return """
ENCRYPTION HANDLER - Command Reference
═══════════════════════════════════════════════════════════════════

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

  encryption hmac verify <data> <hmac> key=<key>
      Verify HMAC signature

  encryption list
      List available encryption capabilities

  encryption help
      Show this help message

═══════════════════════════════════════════════════════════════════

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

For more details on a specific command, use:
  encryption <command> (without arguments to see usage)
    """












def get_harvest_help_display():
    return """
RECON & CREDENTIAL HARVESTING - Command Reference
═══════════════════════════════════════════════════════════════════

COMMANDS:

  harvest recon <agent_id>       Perform comprehensive system/network/user reconnaissance
  harvest creds <agent_id>       Harvest credentials from target (browsers, vault, etc.)
  harvest system <agent_id>      Get detailed system information
  harvest network <agent_id>     Get network configuration and connections
  harvest users <agent_id>       Get user account information
  harvest generate recon_agent   Generate a standalone recon agent with credential harvesting

DESCRIPTION:
  The harvest command provides comprehensive reconnaissance and credential harvesting capabilities.
  It can perform automated information gathering and credential extraction from target systems.

FEATURES:
  • Credential harvesting from browsers (Chrome, Firefox) and system vaults
  • System reconnaissance (OS, architecture, hardware info)
  • Network reconnaissance (IP, interfaces, ARP table)
  • User reconnaissance (user accounts, privileges, groups)
  • Self-contained agent generation with embedded capabilities

EXAMPLES:

  # Harvest credentials from agent
  harvest creds abc123-456def

  # Perform full reconnaissance on agent
  harvest recon xyz789-ghi000

  # Generate a standalone recon agent
  harvest generate recon_agent

NOTE:
  • The recon agent is polymorphic and includes evasion techniques
  • Generated agents have self-destruct functionality when receiving kill commands
  • Harvest commands work with existing NeoC2 infrastructure
    """


def get_save_help_display():
    return """\nFILE SAVING - Command Reference
═══════════════════════════════════════════════════════════════════

COMMANDS:

  save <agent_id> <task_id> [filename]     Save specific task result to loot directory
  save logs <agent_id|all> [limit]         Save all results from specific agent or all agents to logs directory

DESCRIPTION:
  The save command provides functionality to store agent results and downloaded files to local storage.
  Results can be saved to either the loot directory (for individual results) or logs directory (for comprehensive result logs).

FEATURES:
  • Automatic base64 decoding for downloaded files
  • Automatic loot directory creation
  • Full result logging in logs directory
  • Timestamped and organized file storage
  • Support for custom filenames

EXAMPLES:

  # Save a specific task result
  save abc123-456def 12345 custom_output.txt

  # Save all results from a specific agent to logs
  save logs xyz789-ghi000

  # Save all results from all agents to logs (with limit)
  save logs all 100

NOTE:
  • Files with base64 content are automatically decoded
  • Loot directory is used for individual results/downloads
  • Logs directory is used for comprehensive result logs
  • Task results contain full untruncated output for long commands
    """
