package socks

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"dproxy-server-go/socks/auth"
)

func readExactly(stream net.Conn, expectedLength int) ([]byte, error) {
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

func ReadVersionIdentifier(stream net.Conn) (SocksVersionIdentifier, error) {
	buffer, err := readExactly(stream, 2)
	if err != nil {
		return SocksVersionIdentifier{}, err
	}

	ver := buffer[0]
	if ver != 5 {
		return SocksVersionIdentifier{}, errors.New("version not supported")
	}

	nmethods := buffer[1]
	if nmethods == 0 {
		return SocksVersionIdentifier{}, errors.New("no auth method informed")
	}

	authBuffer, err := readExactly(stream, int(nmethods))
	if err != nil {
		return SocksVersionIdentifier{}, err
	}

	authMethods := make([]SocksAuthMethod, nmethods)
	for i := 0; i < int(nmethods); i++ {
		authMethods[i] = SocksAuthMethod(authBuffer[i])
	}

	return SocksVersionIdentifier{
		ver,
		authMethods,
	}, nil
}

func SendMethodSelection(stream net.Conn, method SocksAuthMethod) error {
	buffer := make([]byte, 2)
	buffer[0] = byte(5)
	buffer[1] = byte(method)

	_, err := stream.Write(buffer)
	return err
}

func ReadUsernameAuthRequest(stream net.Conn) (auth.UsernameAuthRequest, error) {
	buffer, err := readExactly(stream, 2)
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	ver := buffer[0]
	if ver != 1 {
		return auth.UsernameAuthRequest{}, errors.New("version not supported")
	}

	ulen := buffer[1]

	buffer, err = readExactly(stream, int(ulen))
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	uname := string(buffer)

	buffer, err = readExactly(stream, 1)
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	plen := buffer[0]

	buffer, err = readExactly(stream, int(plen))
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	passwd := string(buffer)

	return auth.UsernameAuthRequest{
		ver,
		uname,
		passwd,
	}, nil
}

func SendUsernameAuthReply(stream net.Conn, status auth.UsernameAuthReplyStatus) error {
	buffer := make([]byte, 2)
	buffer[0] = 1
	buffer[1] = uint8(status)

	_, err := stream.Write(buffer)
	return err
}

func ReadRequest(stream net.Conn) (SocksRequest, error) {
	buffer, err := readExactly(stream, 4)
	if err != nil {
		return SocksRequest{}, err
	}

	ver := buffer[0]
	if ver != 5 {
		return SocksRequest{}, errors.New("version not supported")
	}

	cmd := SocksCommand(buffer[1])
	atyp := SocksAddressType(buffer[3])
	dstAddr := make([]byte, 0)
	switch atyp {
	case ADDR_IPV4:
		buffer, err := readExactly(stream, 4)
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	case ADDR_DOMAINNAME:
		buffer, err := readExactly(stream, 1)
		if err != nil {
			return SocksRequest{}, err
		}

		buffer, err = readExactly(stream, int(buffer[0]))
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	case ADDR_IPV6:
		buffer, err := readExactly(stream, 16)
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	}

	buffer, err = readExactly(stream, 2)
	if err != nil {
		return SocksRequest{}, err
	}

	dstPort := binary.BigEndian.Uint16(buffer)

	return SocksRequest{
		ver,
		cmd,
		atyp,
		dstAddr,
		dstPort,
	}, nil
}

func SendReply(stream net.Conn, rep SocksReplyType, bndAddr netip.Addr, bndPort uint16) error {
	alen := 4
	if bndAddr.Is6() {
		alen = 16
	}

	buffer := make([]byte, 6+alen)
	buffer[0] = 5
	buffer[1] = uint8(rep)
	buffer[2] = 0
	if bndAddr.Is6() {
		buffer[3] = uint8(ADDR_IPV6)
	} else {
		buffer[3] = uint8(ADDR_IPV4)
	}
	copy(buffer[4:], bndAddr.AsSlice())
	binary.BigEndian.PutUint16(buffer[len(buffer)-2:], bndPort)

	_, err := stream.Write(buffer)
	return err
}
