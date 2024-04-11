package windows_rootkit

import "syscall"

// OpenThread opens an existing thread object and returns a handle to it.
// The returned handle can be used in other thread-related functions.
func OpenThread(dwDesiredAccess uint32, bInheritHandle bool, dwThreadId uint32) (syscall.Handle, error) {
	ret, _, err := ProcOpenThread.Call(uintptr(dwDesiredAccess), uintptr(BoolToUintptr(bInheritHandle)), uintptr(dwThreadId))
	if ret == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}
