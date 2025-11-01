package netutil

import "net"

func ReadExactly(stream net.Conn, expectedLength int) ([]byte, error) {
	var buffer = make([]byte, expectedLength)
	read := 0
	for read < expectedLength {
		n, err := stream.Read(buffer[read:])
		if err != nil {
			return nil, err
		}

		read += n
	}

	return buffer, nil
}
