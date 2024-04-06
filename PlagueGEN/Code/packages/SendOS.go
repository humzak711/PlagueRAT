package packages

import (
	"net"
)

func Send_OS(conn net.Conn, OS_info string) bool {

	// Send OS info to server as UTF-8 encoded string
	_, err := conn.Write([]byte(OS_info))

	// Error handling for sending OS info to server
	return err == nil
}
