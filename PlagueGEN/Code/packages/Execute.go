package packages

import (
	"fmt"
	"os/exec"
	"strings"
)

func Execute_windows(command string) string {
	// Execute the command
	output, err := exec.Command("cmd", "/c", command).CombinedOutput()

	if err != nil {
		return fmt.Sprintf("Error executing command: %s", command)
	}

	return string(output)
}

func Execute_unix(command string) string {
	// Execute the command
	output, err := exec.Command("sh", "-c", command).CombinedOutput()

	if err != nil {
		return fmt.Sprintf("Error executing command: %s", command)
	}

	return string(output)
}

func Execute_android(command string) string {
	// Run the ADB command
	output, err := exec.Command("adb", "shell", command).CombinedOutput()

	if err != nil {
		return fmt.Sprintf("Error executing command: %s", command)
	}

	return string(output)
}

func Execute_on_OS(operating_system string, command string) string {

	var output string // Variable to hold output of command
	switch strings.ToLower(operating_system) {

	case "windows":
		// Windows
		output = Execute_windows(command)

	case "linux", "freebsd", "darwin", "solaris":
		// Operating systems which use Unix
		output = Execute_unix(command)

	case "android":
		// Android devices
		output = Execute_android(command)

	default:
		// Unsupported/Unknown operating system
		output = fmt.Sprintf("Unsupported operating system: %s", operating_system)
	}

	// Return output of command
	return output
}
