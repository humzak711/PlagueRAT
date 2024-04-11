package windows_rootkit

import "runtime"

// Helper function to convert bool to uintptr
func BoolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// Function to check if the operating system is windows
func CheckOsIsWindows() bool {
	var OS string = runtime.GOOS
	if OS == "windows" {
		return true
	} else {
		return false
	}
}
