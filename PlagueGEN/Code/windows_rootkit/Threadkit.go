package windows_rootkit

import "syscall"

// OpenThreadCustom function opens an existing thread object and returns a handle to it.
func OpenThreadCustom(dwDesiredAccess uint32, bInheritHandle bool, dwThreadId uint32) (syscall.Handle, error) {
	ret, _, err := ProcOpenThread.Call(uintptr(dwDesiredAccess), uintptr(BoolToUintptr(bInheritHandle)), uintptr(dwThreadId))
	if ret == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}
