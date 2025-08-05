package socks

import "net"

func GetDestinationAsStr(request SocksRequest) string {
	switch request.Atyp {
	case ADDR_IPV4:
		return net.IP{request.DstAddr[0], request.DstAddr[1], request.DstAddr[2], request.DstAddr[3]}.String()
	case ADDR_DOMAINNAME:
		return string(request.DstAddr)
	case ADDR_IPV6:
		return net.IP{
			request.DstAddr[0], request.DstAddr[1], request.DstAddr[2], request.DstAddr[3],
			request.DstAddr[4], request.DstAddr[5], request.DstAddr[6], request.DstAddr[7],
			request.DstAddr[8], request.DstAddr[9], request.DstAddr[10], request.DstAddr[11],
			request.DstAddr[12], request.DstAddr[13], request.DstAddr[14], request.DstAddr[15],
		}.String()
	}

	return ""
}
