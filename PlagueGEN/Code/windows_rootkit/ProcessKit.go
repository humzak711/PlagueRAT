package windows_rootkit

import (
	"syscall"
	"unsafe"
)

// CreateToolhelp32Snapshot function retrieves a snapshot of the processes, heaps, modules, and threads running in the system
func CreateToolhelp32Snapshot(dwFlags uint32, th32ProcessID uint32) (syscall.Handle, error) {
	ret, _, err := ProcCreateToolhelp32Snapshot.Call(uintptr(dwFlags), uintptr(th32ProcessID))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), err
}

// Process32First function retrieves information about the first process encountered in a system snapshot
func Process32First(hSnapshot syscall.Handle, lppe *ProcessEntry32) (err error) {
	ret, _, err := ProcProcess32First.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// Process32Next function retrieves information about the next process recorded in a system snapshot
func Process32Next(hSnapshot syscall.Handle, lppe *ProcessEntry32) (err error) {
	ret, _, err := ProcProcess32Next.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// OpenProcess function opens an existing local process object
func OpenProcess(dwDesiredAccess uint32, bInheritHandle bool, dwProcessID uint32) (syscall.Handle, error) {
	ret, _, err := ProcOpenProcess.Call(uintptr(dwDesiredAccess), uintptr(BoolToUintptr(bInheritHandle)), uintptr(dwProcessID))
	if ret == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), err
}

// SetProcessDescription function sets the description of the specified process
func SetProcessDescription(hProcess syscall.Handle, lpDescription *uint16) (err error) {
	ret, _, err := ProcSetProcessDescription.Call(uintptr(hProcess), uintptr(unsafe.Pointer(lpDescription)))
	if ret == 0 {
		return err
	}
	return nil
}

// getProcessHandleByName function retrieves the handle of the process by its name
func GetProcessHandleByName(name string) (syscall.Handle, error) {
	// Create a snapshot of running processes
	snapshot, err := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	defer syscall.CloseHandle(snapshot)

	// Initialize a ProcessEntry32 structure for iterating through processes
	var pe32 ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Iterate through processes to find the one with the specified name
	err = Process32First(snapshot, &pe32)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	for {
		exeFile := syscall.UTF16ToString(pe32.ExeFile[:])
		if exeFile == name {
			// Found the process, open its handle
			return OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, false, pe32.ProcessID)
		}

		// Move to the next process
		err = Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	return syscall.InvalidHandle, syscall.ERROR_NOT_FOUND
}

// changeProcessName function changes the name of the process to a new name
func ChangeProcessName(pid syscall.Handle, newName string) error {
	// Change the process name
	name, err := syscall.UTF16FromString(newName)
	if err != nil {
		return err
	}

	// Set the process description (name)
	err = SetProcessDescription(pid, &name[0])
	if err != nil {
		return err
	}

	return nil
}
