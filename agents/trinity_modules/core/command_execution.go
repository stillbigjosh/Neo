// Windows-specific command execution function
func executeCommandHidden(command string) (string, error) {
	if runtime.GOOS != "windows" {
		cmd := exec.Command("sh", "-c", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[ERROR] Command execution failed: %v", err), nil
		}
		if len(output) > 1024*1024 { // 1MB limit
			output = append(output[:1024*1024], []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
		}
		return string(output), nil
	}

	// Detect if this is a PowerShell command
	isPowerShell := isPowerShellCommand(command)

	// Create anonymous pipes for capturing output
	var saAttr SECURITY_ATTRIBUTES
	saAttr.NLength = uint32(unsafe.Sizeof(saAttr))
	saAttr.bInheritHandle = 1 // Set inherit handle to true
	saAttr.LPSecurityDescriptor = 0

	// Create stdout pipe
	var stdoutRead, stdoutWrite uintptr
	ret, _, _ := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stdoutRead)),
		uintptr(unsafe.Pointer(&stdoutWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to create stdout pipe")
	}

	// Create stderr pipe
	var stderrRead, stderrWrite uintptr
	ret, _, _ = procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stderrRead)),
		uintptr(unsafe.Pointer(&stderrWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		return "", fmt.Errorf("failed to create stderr pipe")
	}

	// Prepare the command line
	var cmdLine *uint16
	var shell string
	if isPowerShell {
		// Use PowerShell with hidden window and bypass execution policy
		// For PowerShell commands, we need to handle the output encoding properly
		// to avoid CLIXML output format issues
		encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
		// Use -EncodedCommand with proper parameters to avoid CLIXML
		// Set output encoding to UTF8 and force text output using Out-String
		shell = fmt.Sprintf("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -NonInteractive -Command \"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $script = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s')); $output = & ([scriptblock]::Create($script)) | Out-String; Write-Output $output\"", encodedCommand)
	} else {
		// Use cmd for regular commands
		shell = fmt.Sprintf("cmd /C %s", command)
	}
	cmdLine, err := syscall.UTF16PtrFromString(shell)
	if err != nil {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		syscall.CloseHandle(syscall.Handle(stderrRead))
		syscall.CloseHandle(syscall.Handle(stderrWrite))
		return "", err
	}

	// Initialize STARTUPINFO structure with pipe handles
	var si STARTUPINFO
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
	si.ShowWindow = SW_HIDE // Hide the window
	si.StdInput = 0        // Use default input
	si.StdOutput = stdoutWrite // Redirect stdout to our pipe (child writes to this)
	si.StdError = stderrWrite  // Redirect stderr to our pipe (child writes to this)

	// Initialize PROCESS_INFORMATION structure
	var pi PROCESS_INFORMATION

	// Create the process with hidden window and redirected output
	err = createProcess(
		nil, // applicationName
		cmdLine, // commandLine
		nil, // processAttributes
		nil, // threadAttributes
		true, // inheritHandles - important for pipe inheritance
		CREATE_NO_WINDOW, // creationFlags - this is key for hiding the window
		0, // environment
		nil, // currentDirectory
		&si, // startupInfo
		&pi, // processInformation
	)

	if err != nil {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		syscall.CloseHandle(syscall.Handle(stderrRead))
		syscall.CloseHandle(syscall.Handle(stderrWrite))
		return "", err
	}

	// Close the write handles for both PowerShell and regular commands
	syscall.CloseHandle(syscall.Handle(stdoutWrite))
	syscall.CloseHandle(syscall.Handle(stderrWrite))

	defer syscall.CloseHandle(syscall.Handle(pi.Process))
	defer syscall.CloseHandle(syscall.Handle(pi.Thread))

	stdoutChan := make(chan []byte)
	stderrChan := make(chan []byte)

	go func() {
		var stdoutBytes []byte
		var buffer [4096]byte
		var bytesRead uint32
		totalRead := 0
		const maxSize = 1024 * 1024 // 1MB limit

		for {
			// Check if we've reached the size limit
			if totalRead >= maxSize {
				stdoutBytes = append(stdoutBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			ret, _, _ := procReadFile.Call(
				stdoutRead,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			// Only continue if we successfully read data and haven't exceeded size
			if ret == 0 || bytesRead == 0 {
				break
			}

			// Check if adding this chunk would exceed our size limit
			if totalRead + int(bytesRead) > maxSize {
				// Only add what fits within our limit
				remaining := maxSize - totalRead
				stdoutBytes = append(stdoutBytes, buffer[:remaining]...)
				stdoutBytes = append(stdoutBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			stdoutBytes = append(stdoutBytes, buffer[:bytesRead]...)
			totalRead += int(bytesRead)
		}
		stdoutChan <- stdoutBytes
	}()

	go func() {
		var stderrBytes []byte
		var buffer [4096]byte
		var bytesRead uint32
		totalRead := 0
		const maxSize = 1024 * 1024 // 1MB limit

		for {
			// Check if we've reached the size limit
			if totalRead >= maxSize {
				stderrBytes = append(stderrBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			ret, _, _ := procReadFile.Call(
				stderrRead,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			// Only continue if we successfully read data and haven't exceeded size
			if ret == 0 || bytesRead == 0 {
				break
			}

			// Check if adding this chunk would exceed our size limit
			if totalRead + int(bytesRead) > maxSize {
				// Only add what fits within our limit
				remaining := maxSize - totalRead
				stderrBytes = append(stderrBytes, buffer[:remaining]...)
				stderrBytes = append(stderrBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			stderrBytes = append(stderrBytes, buffer[:bytesRead]...)
			totalRead += int(bytesRead)
		}
		stderrChan <- stderrBytes
	}()

	result, err := syscall.WaitForSingleObject(syscall.Handle(pi.Process), 60000) // 60 second timeout
	if err != nil || result == syscall.WAIT_TIMEOUT {
		// If timeout occurs, try to terminate the process gracefully
		syscall.TerminateProcess(syscall.Handle(pi.Process), 255)
		return fmt.Sprintf("[ERROR] Command execution timed out after 60 seconds"), nil
	}

	stdoutBytes := <-stdoutChan
	stderrBytes := <-stderrChan

	// Close the read handles
	syscall.CloseHandle(syscall.Handle(stdoutRead))
	syscall.CloseHandle(syscall.Handle(stderrRead))

	output := string(stdoutBytes) + string(stderrBytes)

	// Get the exit code of the process
	var exitCode uint32
	procGetExitCodeProcess.Call(
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&exitCode)),
	)

	// If no output and process exited with error, return error info
	if len(output) == 0 && exitCode != 0 {
		return fmt.Sprintf("[ERROR] Command execution failed with exit code: %d", exitCode), nil
	}

	// For PowerShell commands, we need to clean up CLIXML output if present
	if isPowerShell {
		output = cleanPowerShellOutput(output)
	}

	if output == "" {
		return "[Command executed successfully - no output]", nil
	}

	return output, nil
}

// cleanPowerShellOutput removes CLIXML formatting and other PowerShell artifacts
func cleanPowerShellOutput(output string) string {
	// Remove CLIXML header if present
	if strings.Contains(output, "#< CLIXML") {
		// Remove the CLIXML header
		output = strings.Replace(output, "#< CLIXML\n", "", 1)

		// Remove CLIXML error tags (S, E) and convert them to plain text
		// These are PowerShell's internal XML formatting tags
		output = strings.ReplaceAll(output, "<S S=\"Error\">", "")
		output = strings.ReplaceAll(output, "</S>", "")
		output = strings.ReplaceAll(output, "<S S=\"Output\">", "")
		output = strings.ReplaceAll(output, "<S S=\"Info\">", "")
		output = strings.ReplaceAll(output, "<S S=\"Warning\">", "")
		output = strings.ReplaceAll(output, "<S S=\"Verbose\">", "")
		output = strings.ReplaceAll(output, "<S S=\"Debug\">", "")
		output = strings.ReplaceAll(output, "_x000D__x000A_", "\r\n")
		output = strings.ReplaceAll(output, "_x000A_", "\n")
		output = strings.ReplaceAll(output, "_x000D_", "\r")

		// Remove PowerShell XML objects like progress indicators, etc.
		output = cleanPowerShellXMLObjects(output)

		// Remove any remaining XML-like tags
		output = removeXMLTags(output)
	}

	return output
}

// removeXMLTags removes any remaining XML-like tags from PowerShell output
func removeXMLTags(input string) string {
	// Remove XML tags like <Obj>, <TN>, <MS>, etc. using string replacement
	// since we can't rely on regex package in all contexts

	// First, find and remove all XML tags
	result := input
	for {
		start := strings.Index(result, "<")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], ">")
		if end == -1 {
			break
		}
		end = start + end + 1
		result = result[:start] + result[end:]
	}

	return result
}

// Additional function to clean PowerShell progress and other XML elements
func cleanPowerShellXMLObjects(output string) string {
	// Handle PowerShell progress objects and other XML elements
	// Look for <Obj> tags and their content which are PowerShell's internal objects
	for {
		objStart := strings.Index(output, "<Obj")
		if objStart == -1 {
			break
		}
		objEnd := strings.Index(output[objStart:], "</Obj>")
		if objEnd == -1 {
			break
		}
		objEnd = objStart + objEnd + 6 // +6 for "</Obj>"
		output = output[:objStart] + output[objEnd:]
	}

	// Also handle other PowerShell XML objects like <TN> (Type Name), <MS> (Member Set), etc.
	for {
		tagStart := strings.Index(output, "<TN")
		if tagStart == -1 {
			break
		}
		tagEnd := strings.Index(output[tagStart:], "</TN>")
		if tagEnd == -1 {
			break
		}
		tagEnd = tagStart + tagEnd + 5 // +5 for "</TN>"
		output = output[:tagStart] + output[tagEnd:]
	}

	for {
		tagStart := strings.Index(output, "<MS")
		if tagStart == -1 {
			break
		}
		tagEnd := strings.Index(output[tagStart:], "</MS>")
		if tagEnd == -1 {
			break
		}
		tagEnd = tagStart + tagEnd + 5 // +5 for "</MS>"
		output = output[:tagStart] + output[tagEnd:]
	}

	return output
}

// isPowerShellCommand detects if a command is a PowerShell command based on common PowerShell patterns
func isPowerShellCommand(command string) bool {
	// Convert to lowercase for pattern matching
	cmdLower := strings.ToLower(command)

	// Check for PowerShell-specific patterns
	powerShellPatterns := []string{
		"$",                    // PowerShell variables
		"get-",                 // PowerShell cmdlets
		"set-",                 // PowerShell cmdlets
		"new-",                 // PowerShell cmdlets
		"remove-",              // PowerShell cmdlets
		"invoke-",              // PowerShell cmdlets
		"select-",              // PowerShell cmdlets
		"where-",               // PowerShell cmdlets
		"foreach-",             // PowerShell cmdlets
		"out-",                 // PowerShell cmdlets
		"export-",              // PowerShell cmdlets
		"import-",              // PowerShell cmdlets
		"write-",               // PowerShell cmdlets
		"read-",                // PowerShell cmdlets
		"clear-",               // PowerShell cmdlets
		"update-",              // PowerShell cmdlets
		"get-service",          // PowerShell cmdlets
		"get-wmiobject",        // PowerShell cmdlets
		"get-ciminstance",      // PowerShell cmdlets
		"start-process",        // PowerShell cmdlets
		"stop-service",         // PowerShell cmdlets
		"restart-service",      // PowerShell cmdlets
		"set-service",          // PowerShell cmdlets
		"try {",                // PowerShell try-catch blocks
		"catch {",              // PowerShell try-catch blocks
		"finally {",            // PowerShell try-catch blocks
		"get-itemproperty",     // Registry operations
		"set-itemproperty",     // Registry operations
		"new-object",           // PowerShell object creation
		"add-type",             // PowerShell type definitions
	}

	// Count matching patterns
	patternCount := 0
	for _, pattern := range powerShellPatterns {
		if strings.Contains(cmdLower, pattern) {
			patternCount++
			// If we find 2 or more PowerShell patterns, it's likely a PowerShell command
			if patternCount >= 2 {
				return true
			}
		}
	}

	// Additional check: if it has PowerShell variable assignment pattern
	if strings.Contains(cmdLower, "$") && (strings.Contains(cmdLower, " = ") || strings.Contains(cmdLower, "=")) {
		return true
	}

	return patternCount > 0
}