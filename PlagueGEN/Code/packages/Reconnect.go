package packages

import (
	"fmt"
	"net"
	"time"
)

func Reconnect(conn *net.Conn, server_address string, conn_update chan<- *net.Conn) {

	// Infinite loop to constantly check for connection errors
	for {

		// Second check if current client - server connection is valid
		if !IsConnActive(*conn) {

			// Attempt to reconnect to the server
			fmt.Println("Attempting to reconnect to server...")
			new_conn, err := ConnectToServer(server_address)
			if err == nil {
				*conn = new_conn // Update the connection

				// Notify the handler about the updated connection
				conn_update <- conn
			}
		}
		time.Sleep(1 * time.Second) // Prevent high CPU usage
	}
}
