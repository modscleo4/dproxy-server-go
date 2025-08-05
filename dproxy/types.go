/**
 * Copyright 2025 Dhiego Cassiano Fogaça Barbosa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dproxy

type DProxyPacketType uint8

const (
	HANDSHAKE_INIT DProxyPacketType = iota
	HANDSHAKE_RESPONSE
	HANDSHAKE_FINAL
	HANDSHAKE_FINALIZED
	CONNECT
	CONNECTED
	DISCONNECT
	DISCONNECTED
	DATA
	ENCRYPTED_DATA
	HEARTBEAT
	HEARTBEAT_RESPONSE
	ERROR
)

type DProxyError uint8

const (
	NO_ERROR DProxyError = iota
	INVALID_VERSION
	INVALID_PACKET_TYPE
	INVALID_PACKET_LENGTH
	INVALID_HANDSHAKE_INFO
	HANDSHAKE_FAILED
	ALREADY_AUTHENTICATED
	INVALID_DESTINATION
	CONNECTION_FAILED
	CONNECTION_CLOSED
	CONNECTION_TIMEOUT
	INVALID_CONNECTION
	DECRYPT_FAILED
)

type DProxyHeader struct {
	Version   uint8
	Type      DProxyPacketType
	Length    uint16
	ErrorCode DProxyError
}

type DProxyHandshakeInit struct {
	DProxyHeader
	DERPublicKey []byte
}

type DProxyHandshakeResponse struct {
	DProxyHeader
	IV                []byte
	Ciphertext        []byte
	AuthenticationTag []byte
}

type DProxyHandshakeFinal struct {
	DProxyHeader
	Plaintext []byte
}

type DProxyHandshakeFinalized struct {
	DProxyHeader
	Id string
}

type DProxyConnect struct {
	DProxyHeader
	ConnectionId uint32
	Destination  string
	Port         uint16
}

type DProxyConnected struct {
	DProxyHeader
	ConnectionId uint32
	Address      string
}

type DProxyDisconnect struct {
	DProxyHeader
	ConnectionId uint32
}

type DProxyDisconnected struct {
	DProxyHeader
	ConnectionId uint32
}

type DProxyData struct {
	DProxyHeader
	ConnectionId uint32
	Data         []byte
}

type DProxyEncryptedData struct {
	DProxyHeader
	ConnectionId      uint32
	IV                []byte
	Ciphertext        []byte
	AuthenticationTag []byte
}

type DProxyHeartbeat struct {
	DProxyHeader
	Timestamp uint64
}

type DProxyHeartbeatResponse struct {
	DProxyHeader
	Timestamp uint64
	Latency   uint32
}

type DProxyErrorPacket struct {
	DProxyHeader
	Message string
}
