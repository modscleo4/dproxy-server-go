package socks

type SocksCommand uint8

const (
	CMD_CONNECT       SocksCommand = 0x01
	CMD_BIND                       = 0x02
	CMD_UDP_ASSOCIATE              = 0x03
)

type SocksAddressType uint8

const (
	ADDR_IPV4       SocksAddressType = 0x01
	ADDR_DOMAINNAME SocksAddressType = 0x03
	ADDR_IPV6       SocksAddressType = 0x04
)

type SocksAuthMethod uint8

const (
	AUTH_NO_AUTHENTICATION_REQUIRED SocksAuthMethod = iota
	AUTH_GSSAPI
	AUTH_USERNAME_PASSWORD
	AUTH_NO_ACCEPTABLE_METHODS = 0xFF
)

type SocksReplyType uint8

const (
	REPLY_SUCCEEDED SocksReplyType = iota
	REPLY_GENERAL_SOCKS_SERVER_FAILURE
	REPLY_CONNECTION_NOT_ALLOWED_BY_RULESET
	REPLY_NETWORK_UNREACHABLE
	REPLY_HOST_UNREACHABLE
	REPLY_CONNECTION_REFUSED
	REPLY_TTL_EXPIRED
	REPLY_COMMAND_NOT_SUPPORTED
	REPLY_ADDRESS_TYPE_NOT_SUPPORTED
)

type SocksVersionIdentifier struct {
	Ver     uint8
	Methods []SocksAuthMethod
}

type SocksMethodSelection struct {
	Ver    uint8
	Method SocksAuthMethod
}

type SocksRequest struct {
	Ver     uint8
	Cmd     SocksCommand
	Atyp    SocksAddressType
	DstAddr []byte
	DstPort uint16
}

type SocksReply struct {
	Ver     uint8
	Rep     SocksReplyType
	Atyp    SocksAddressType
	BndAddr []byte
	BndPort uint16
}

type SocksUdpRequest struct {
	Frag    uint8
	Atyp    SocksAddressType
	DstAddr []byte
	DstPort uint16
	Data    []byte
}
