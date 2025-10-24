package socks

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"dproxy-server-go/pkg/internal/netutil"
	"dproxy-server-go/pkg/socks/auth"
)

func ReadVersionIdentifier(stream net.Conn) (SocksVersionIdentifier, error) {
	buffer, err := netutil.ReadExactly(stream, 2)
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

	authBuffer, err := netutil.ReadExactly(stream, int(nmethods))
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
	buffer, err := netutil.ReadExactly(stream, 2)
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	ver := buffer[0]
	if ver != 1 {
		return auth.UsernameAuthRequest{}, errors.New("version not supported")
	}

	ulen := buffer[1]

	buffer, err = netutil.ReadExactly(stream, int(ulen))
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	uname := string(buffer)

	buffer, err = netutil.ReadExactly(stream, 1)
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	plen := buffer[0]

	buffer, err = netutil.ReadExactly(stream, int(plen))
	if err != nil {
		return auth.UsernameAuthRequest{}, err
	}

	passwd := string(buffer)

	return auth.UsernameAuthRequest{
		Ver:    ver,
		Uname:  uname,
		Passwd: passwd,
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
	buffer, err := netutil.ReadExactly(stream, 4)
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
		buffer, err := netutil.ReadExactly(stream, 4)
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	case ADDR_DOMAINNAME:
		buffer, err := netutil.ReadExactly(stream, 1)
		if err != nil {
			return SocksRequest{}, err
		}

		buffer, err = netutil.ReadExactly(stream, int(buffer[0]))
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	case ADDR_IPV6:
		buffer, err := netutil.ReadExactly(stream, 16)
		if err != nil {
			return SocksRequest{}, err
		}

		dstAddr = buffer
		break
	}

	buffer, err = netutil.ReadExactly(stream, 2)
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
