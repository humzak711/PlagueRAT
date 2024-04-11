package windows_rootkit

// Helper function to convert bool to uintptr
func BoolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
