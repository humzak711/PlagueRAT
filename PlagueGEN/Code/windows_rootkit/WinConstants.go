package windows_rootkit

import (
	"syscall"
)

// Constants for Windows API
const (
	PROCESS_QUERY_INFORMATION   = 0x0400
	PROCESS_VM_READ             = 0x0010
	PROCESS_VM_WRITE            = 0x0020
	PROCESS_VM_OPERATION        = 0x0008
	PROCESS_ALL_ACCESS          = 0x1F0FFF
	SE_PRIVILEGE_ENABLED        = 0x00000002
	HIGH_PRIORITY_CLASS         = 0x00000080
	NORMAL_PRIORITY_CLASS       = 0x00000020
	BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
	TH32CS_SNAPPROCESS          = 0x00000002
	TH32CS_SNAPMODULE           = 0x00000008
	TH32CS_SNAPMODULE32         = 0x00000010

	MAX_PATH          = 260
	MAX_MODULE_NAME32 = 255

	THREAD_SUSPEND_RESUME = 0x2

	CONTEXT_FULL    = 0x10007
	CONTEXT_INTEGER = 0x10002

	MEM_COMMIT   = 0x1000
	MEM_RESERVE  = 0x2000
	MEM_RELEASE  = 0x8000
	MEM_DECOMMIT = 0x4000

	PAGE_READWRITE   = 0x04
	IMAGE_DOS_HEADER = 0x40
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
	ReadProcessMemory            *syscall.LazyProc = Kernel32DLL.NewProc("ReadProcessMemory")
	ProcCreateRemoteThread       *syscall.LazyProc = Kernel32DLL.NewProc("CreateRemoteThread")

	// advapi32
	procOpenProcessToken      *syscall.LazyProc = Modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   *syscall.LazyProc = Modadvapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeValueW *syscall.LazyProc = Modadvapi32.NewProc("LookupPrivilegeValueW")
)
