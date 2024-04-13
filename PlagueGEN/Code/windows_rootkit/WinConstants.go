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
	PROCESS_ALL_ACCESS        = 0x1F0FFF
	SE_PRIVILEGE_ENABLED      = 0x00000002
	TH32CS_SNAPPROCESS        = 0x00000002
	TH32CS_SNAPTHREAD         = 0x00000004

	MAX_PATH          = 260
	MAX_MODULE_NAME32 = 255

	THREAD_SUSPEND_RESUME = 0x2

	CONTEXT_FULL    = 0x10007
	CONTEXT_INTEGER = 0x10002

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
)

// Functions from Windows API
var (
	// LazyLoad DLL's
	Kernel32DLL *syscall.LazyDLL = syscall.NewLazyDLL("kernel32.dll")
	Modadvapi32 *syscall.LazyDLL = syscall.NewLazyDLL("advapi32.dll")

	// kernel32API
	ProcCreateToolhelp32Snapshot *syscall.LazyProc = Kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	ProcModule32First            *syscall.LazyProc = Kernel32DLL.NewProc("Module32First")
	ProcModule32Next             *syscall.LazyProc = Kernel32DLL.NewProc("Module32Next")
	ProcProcess32First           *syscall.LazyProc = Kernel32DLL.NewProc("Process32First")
	ProcProcess32Next            *syscall.LazyProc = Kernel32DLL.NewProc("Process32Next")
	ProcOpenProcess              *syscall.LazyProc = Kernel32DLL.NewProc("OpenProcess")
	ProcOpenThread               *syscall.LazyProc = Kernel32DLL.NewProc("OpenThread")
	ProcSuspendThread            *syscall.LazyProc = Kernel32DLL.NewProc("SuspendThread")
	ProcResumeThread             *syscall.LazyProc = Kernel32DLL.NewProc("ResumeThread")
	ProcGetThreadContext         *syscall.LazyProc = Kernel32DLL.NewProc("GetThreadContext")
	ProcSetThreadContext         *syscall.LazyProc = Kernel32DLL.NewProc("SetThreadContext")
	ProcGetPriorityClass         *syscall.LazyProc = Kernel32DLL.NewProc("GetPriorityClass")
	VirtualAllocEx               *syscall.LazyProc = Kernel32DLL.NewProc("VirtualAllocEx")
	WriteProcessMemory           *syscall.LazyProc = Kernel32DLL.NewProc("WriteProcessMemory")
	ProcThread32Next             *syscall.LazyProc = Kernel32DLL.NewProc("Thread32Next")
	ProcThread32First            *syscall.LazyProc = Kernel32DLL.NewProc("Thread32First")

	// advapi32
	ProcOpenProcessToken      *syscall.LazyProc = Modadvapi32.NewProc("OpenProcessToken")
	ProcLookupPrivilegeValueW *syscall.LazyProc = Modadvapi32.NewProc("LookupPrivilegeValueW")
)
