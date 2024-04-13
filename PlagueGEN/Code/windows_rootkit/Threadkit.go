package windows_rootkit

import (
	"syscall"
	"unsafe"
)

// Thread32FirstCustom function retrieves information about the first thread encountered in a system snapshot.
func Thread32FirstCustom(hSnapshot syscall.Handle, lppe *ThreadEntry32) error {
	ret, _, err := ProcThread32First.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// Thread32NextCustom function retrieves information about the next thread recorded in a system snapshot.
func Thread32NextCustom(hSnapshot syscall.Handle, lppe *ThreadEntry32) error {
	ret, _, err := ProcThread32Next.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	if ret == 0 {
		return err
	}
	return nil
}

// OpenThreadCustom function opens an existing thread object and returns a handle to it.
func OpenThreadCustom(dwDesiredAccess uint32, bInheritHandle bool, dwThreadId uint32) (syscall.Handle, error) {
	ret, _, err := ProcOpenThread.Call(uintptr(dwDesiredAccess), uintptr(BoolToUintptr(bInheritHandle)), uintptr(dwThreadId))
	if ret == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}

// GetThreadIDByProcessID function gets the thread ID by process ID.
func GetThreadIDByProcessID(processID uint32) (uint32, error) {
	snapshot, err := CreateToolhelp32SnapshotCustom(TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(snapshot)

	var te32 ThreadEntry32
	te32.Size = uint32(unsafe.Sizeof(te32))

	err = Thread32FirstCustom(snapshot, &te32)
	if err != nil {
		return 0, err
	}

	for {
		if te32.OwnerProcessID == processID {
			return te32.ThreadID, nil
		}
		err = Thread32NextCustom(snapshot, &te32)
		if err != nil {
			break
		}
	}

	return 0, syscall.ERROR_NOT_FOUND
}
