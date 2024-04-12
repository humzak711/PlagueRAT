package windows_rootkit

// ProcessEntry32 structure represents a process entry in the snapshot, providing information about a specific process.
type ProcessEntry32 struct {
	Size            uint32           // The size of the structure, in bytes.
	Usage           uint32           // Usage count of the module.
	ProcessID       uint32           // The process identifier.
	DefaultHeapID   uintptr          // Handle to the default heap of the process.
	ModuleID        uint32           // Identifier of the module associated with the entry.
	Threads         uint32           // Number of threads in the process.
	ParentProcessID uint32           // The process identifier of the parent process.
	PriClassBase    int32            // Base priority of the process.
	Flags           uint32           // Flags indicating attributes of the process.
	ExeFile         [MAX_PATH]uint16 // Path to the executable file.
}

// MODULEENTRY32 structure represents a module in the snapshot.
type MODULEENTRY32 struct {
	Size         uint32                      // The size of the structure, in bytes.
	ModuleID     uint32                      // The identifier of the module.
	ProcessID    uint32                      // The identifier of the process that contains the module.
	GlblcntUsage uint32                      // Global usage count.
	ProccntUsage uint32                      // Process usage count.
	BaseAddress  uintptr                     // The base address of the module in the process's address space.
	BaseSize     uint32                      // The size of the module.
	Handle       uintptr                     // The module's handle.
	ModuleName   [MAX_MODULE_NAME32 + 1]byte // The name of the module.
	ExePath      [MAX_PATH]byte              // The path to the module executable.
}

// IMAGE_OPTIONAL_HEADER32 structure represents the optional header of a PE (Portable Executable) file.
type IMAGE_OPTIONAL_HEADER32 struct {
	AddressOfEntryPoint uint32 // The entry point address of the executable code.
}

// LUID structure represents a locally unique identifier.
type LUID struct {
	LowPart  uint32 // Low-order part of the identifier.
	HighPart int32  // High-order part of the identifier.
}

// LUIDAndAttributes structure represents a locally unique identifier and its attributes.
type LUIDAndAttributes struct {
	Luid       LUID   // The locally unique identifier.
	Attributes uint32 // Attributes associated with the identifier.
}

// TOKEN_PRIVILEGES structure represents the privileges associated with a user access token.
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32              // The number of privileges in the array.
	Privileges     []LUIDAndAttributes // Array of locally unique identifiers and their attributes.
}

// Context structure representing the context of a thread
type Context struct {
	ContextFlags                                                                 uint32
	Rax, Rbx, Rcx, Rdx                                                           uint64
	Rsi, Rdi, Rbp                                                                uint64
	Rsp, Rip                                                                     uint64
	R8, R9, R10, R11                                                             uint64
	R12, R13, R14, R15                                                           uint64
	Rflags                                                                       uint32
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs                                     uint16
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                                                 uint64
	FloatSave                                                                    [512]byte
	VectorRegister                                                               [256]byte
	VectorControl, DebugControl                                                  uint64
	LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip uint64
}
