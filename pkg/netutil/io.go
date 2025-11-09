package netutil

import (
	"io"
	"net"
)

func ReadExactly(stream net.Conn, expectedLength int) ([]byte, error) {
	var buffer = make([]byte, expectedLength)
	n, err := io.ReadFull(stream, buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}
