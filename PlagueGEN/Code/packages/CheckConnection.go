package packages

import (
	"net"
)

func IsConnActive(conn net.Conn) bool {
	// Check if the connection is still active by sending a ping message
	_, err := conn.Write([]byte("P1NGS3RV3R"))
	return err == nil
}
