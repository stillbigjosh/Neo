// Windows constants
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
	PAGE_EXECUTE_READ = 0x20

	PROCESS_ALL_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME

	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH = 260

	CREATE_NEW_CONSOLE = 0x00000010
	CREATE_NO_WINDOW = 0x08000000
	STARTF_USESHOWWINDOW = 0x00000001
	STARTF_USESTDHANDLES = 0x00000100
	SW_HIDE = 0

	FILE_ATTRIBUTE_NORMAL = 0x00000080
	INVALID_HANDLE_VALUE = 0xFFFFFFFF

	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE = 0x00004550
	IMAGE_FILE_MACHINE_I386 = 0x014c
	IMAGE_FILE_MACHINE_AMD64 = 0x8664
	IMAGE_FILE_RELOCS_STRIPPED = 0x0001
	IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
	IMAGE_FILE_MACHINE_UNKNOWN = 0

	// Additional constants for advanced shellcode injection
	THREAD_ALL_ACCESS = 0x1F03FF
	THREAD_CREATE_FLAGS_SUSPENDED = 0x00000004
	THREAD_SET_CONTEXT = 0x0010
	THREAD_QUERY_INFORMATION = 0x0040
	THREAD_GET_CONTEXT = 0x0008
	THREAD_SUSPEND_RESUME = 0x0002
)

// Windows structures
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
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15 uint64
	Rip uint64
	/* Control flags */
	EFlags uint32
	/* Segment values */
	Cs, Ss, Ds, Es, Fs, Gs uint16
}

// Structures for advanced shellcode injection
type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// Thread enumeration structures
type THREADENTRY32 struct {
	Size          uint32
	Usage         uint32
	ThreadID      uint32
	OwnerProcessID uint32
	BasePri       int32
	DeltaPri      int32
	Flags         uint32
}