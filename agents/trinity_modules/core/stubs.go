// Stub functions for disabled features
func (a *{AGENT_STRUCT_NAME}) handleBOF_stub(command string) string {
    return "[ERROR] BOF execution is not available in this agent build"
}

func (a *{AGENT_STRUCT_NAME}) handleDotNetAssembly_stub(command string) string {
    return "[ERROR] .NET assembly execution is not available in this agent build"
}

func (a *{AGENT_STRUCT_NAME}) getProcessId_stub(processName string) (uint32, error) {
    return 0, fmt.Errorf("Process ID lookup is not available in this agent build")
}

func (a *{AGENT_STRUCT_NAME}) injectShellcode_stub(shellcode []byte) string {
    return "[ERROR] Shellcode injection is not available in this agent build"
}

func (a *{AGENT_STRUCT_NAME}) injectPE_stub(peData []byte) string {
    return "[ERROR] PE injection is not available in this agent build"
}

func (a *{AGENT_STRUCT_NAME}) executePE_stub(peData []byte, args []string) (string, error) {
    return "[ERROR] PE execution is not available in this agent build", fmt.Errorf("PE execution is not available in this agent build")
}

func (a *{AGENT_STRUCT_NAME}) startReverseProxy_stub() {
    // Do nothing - reverse proxy not available
    // Use context and url to avoid "import not used" error when feature is disabled
    _ = context.Background()
    _, _ = url.Parse("http://example.com")
}

func (a *{AGENT_STRUCT_NAME}) stopReverseProxy_stub() {
    // Do nothing - reverse proxy not available
}

func (a *{AGENT_STRUCT_NAME}) handleSOCKS5_stub(serverConn net.Conn) {
    // Do nothing - reverse proxy not available
    // Use binary package to avoid "import not used" error
    _ = binary.LittleEndian
}

func (a *{AGENT_STRUCT_NAME}) checkSandbox_stub() bool {
    return false // No sandbox check, return false
}

func (a *{AGENT_STRUCT_NAME}) checkProcessesForSandbox_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkWindowsProcessesForSandbox_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkNetworkTools_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkDebuggers_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkProcessesForDebuggers_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkWindowsProcessesForDebuggers_stub() bool {
    return false
}

func (a *{AGENT_STRUCT_NAME}) checkWindowsDebugger_stub() bool {
    return false
}