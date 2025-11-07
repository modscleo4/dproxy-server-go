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

import (
	"encoding/binary"
	"fmt"
	"net"

	"dproxy-server-go/pkg/netutil"
)

func serializePacket(header DProxyHeader, data []byte) []byte {
	var buffer = make([]byte, 5+len(data))
	buffer[0] = header.Version
	buffer[1] = byte(header.Type)
	binary.BigEndian.PutUint16(buffer[2:4], header.Length)
	buffer[4] = byte(header.ErrorCode)
	copy(buffer[5:], data)

	return buffer
}

func GetPacketHeader(stream net.Conn) (DProxyHeader, error) {
	buffer, err := netutil.ReadExactly(stream, 5)
	if err != nil {
		return DProxyHeader{}, err
	}

	var header = DProxyHeader{
		buffer[0],
		DProxyPacketType(buffer[1]),
		binary.BigEndian.Uint16(buffer[2:4]),
		DProxyError(buffer[4]),
	}
	return header, nil
}

func ReadHandshakeInit(stream net.Conn, header DProxyHeader) (DProxyHandshakeInit, error) {
	if header.Type != HANDSHAKE_INIT {
		return DProxyHandshakeInit{}, fmt.Errorf(ErrorUnexpectedType, HANDSHAKE_INIT, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyHandshakeInit{}, err
	}

	var keyLength = binary.BigEndian.Uint16(buffer[0:2])
	var derPublicKey = buffer[2 : 2+keyLength]

	var helloLength = binary.BigEndian.Uint16(buffer[2+keyLength : 2+keyLength+2])
	var hello = string(buffer[2+keyLength+2 : 2+keyLength+2+helloLength])

	return DProxyHandshakeInit{header, derPublicKey, hello}, nil
}

func SendHandshakeResponse(stream net.Conn, iv []byte, ciphertext []byte, authenticationTag []byte) (int, error) {
	var buffer = make([]byte, 14+len(ciphertext)+len(authenticationTag))
	copy(buffer[0:12], iv)
	binary.BigEndian.PutUint16(buffer[12:14], uint16(len(ciphertext)))
	copy(buffer[14:], ciphertext)
	copy(buffer[14+len(ciphertext):], authenticationTag)

	var header = DProxyHeader{1, HANDSHAKE_RESPONSE, uint16(14 + len(ciphertext) + len(authenticationTag)), NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadHandshakeFinal(stream net.Conn, header DProxyHeader) (DProxyHandshakeFinal, error) {
	if header.Type != HANDSHAKE_FINAL {
		return DProxyHandshakeFinal{}, fmt.Errorf(ErrorUnexpectedType, HANDSHAKE_FINAL, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyHandshakeFinal{}, err
	}

	var plaintextLength = binary.BigEndian.Uint16(buffer[0:2])
	var plaintext = buffer[2 : 2+plaintextLength]

	return DProxyHandshakeFinal{header, plaintext}, nil
}

func SendHandshakeFinalized(stream net.Conn, Id string) (int, error) {
	var buffer = make([]byte, 2+len(Id))
	binary.BigEndian.PutUint16(buffer[0:2], uint16(len(Id)))
	copy(buffer[2:], Id)

	var header = DProxyHeader{1, HANDSHAKE_FINALIZED, 0, NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func SendConnect(stream net.Conn, connectionId uint32, destination string, port uint16) (int, error) {
	var buffer = make([]byte, 4+2+len(destination)+2)
	binary.BigEndian.PutUint32(buffer[0:4], connectionId)
	binary.BigEndian.PutUint16(buffer[4:6], uint16(len(destination)))
	copy(buffer[6:], destination)
	binary.BigEndian.PutUint16(buffer[6+len(destination):], port)

	var header = DProxyHeader{1, CONNECT, uint16(4 + 2 + len(destination) + 2), NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadConnected(stream net.Conn, header DProxyHeader) (DProxyConnected, error) {
	if header.Type != CONNECTED {
		return DProxyConnected{}, fmt.Errorf(ErrorUnexpectedType, CONNECTED, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyConnected{}, err
	}

	var connectionId = binary.BigEndian.Uint32(buffer[0:4])
	var addressLength = binary.BigEndian.Uint16(buffer[4:6])
	var address = string(buffer[6 : 6+addressLength])
	var port = binary.BigEndian.Uint16(buffer[6+addressLength : 6+addressLength+2])
	return DProxyConnected{header, connectionId, address, port}, nil
}

func SendDisconnect(stream net.Conn, connectionId uint32) (int, error) {
	var buffer = make([]byte, 4)
	binary.BigEndian.PutUint32(buffer[0:4], connectionId)

	var header = DProxyHeader{1, DISCONNECT, 4, NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadDisconnected(stream net.Conn, header DProxyHeader) (DProxyDisconnected, error) {
	if header.Type != DISCONNECTED {
		return DProxyDisconnected{}, fmt.Errorf(ErrorUnexpectedType, DISCONNECTED, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyDisconnected{}, err
	}

	var connectionId = binary.BigEndian.Uint32(buffer[0:4])
	return DProxyDisconnected{header, connectionId}, nil
}

func ReadData(stream net.Conn, header DProxyHeader) (DProxyData, error) {
	if header.Type != DATA {
		return DProxyData{}, fmt.Errorf(ErrorUnexpectedType, DATA, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyData{}, err
	}

	var connectionId = binary.BigEndian.Uint32(buffer[0:4])
	var dataLength = binary.BigEndian.Uint16(buffer[4:6])
	var data = buffer[6 : 6+dataLength]

	return DProxyData{header, connectionId, data}, nil
}

func SendData(stream net.Conn, connectionId uint32, data []byte) (int, error) {
	var buffer = make([]byte, 4+2+len(data))
	binary.BigEndian.PutUint32(buffer[0:4], connectionId)
	binary.BigEndian.PutUint16(buffer[4:6], uint16(len(data)))
	copy(buffer[6:], data)

	var header = DProxyHeader{1, DATA, 4 + 2 + uint16(len(data)), NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadEncryptedData(stream net.Conn, header DProxyHeader) (DProxyEncryptedData, error) {
	if header.Type != ENCRYPTED_DATA {
		return DProxyEncryptedData{}, fmt.Errorf(ErrorUnexpectedType, ENCRYPTED_DATA, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyEncryptedData{}, err
	}

	var connectionId = binary.BigEndian.Uint32(buffer[0:4])
	var iv = buffer[4:16]
	var ciphertextLength = binary.BigEndian.Uint16(buffer[16:18])
	var ciphertext = buffer[18 : 18+ciphertextLength]
	var authenticationTag = buffer[18+ciphertextLength:]

	return DProxyEncryptedData{header, connectionId, iv, ciphertext, authenticationTag}, nil
}

func SendEncryptedData(
	stream net.Conn,
	connectionId uint32,
	iv []byte,
	ciphertext []byte,
	authenticationTag []byte,
) (int, error) {
	var buffer = make([]byte, 4+12+2+len(ciphertext)+len(authenticationTag))
	binary.BigEndian.PutUint32(buffer[0:4], connectionId)
	copy(buffer[4:16], iv)
	binary.BigEndian.PutUint16(buffer[16:18], uint16(len(ciphertext)))
	copy(buffer[18:], ciphertext)
	copy(buffer[18+len(ciphertext):], authenticationTag)

	var header = DProxyHeader{1, ENCRYPTED_DATA, 4 + 12 + 2 + uint16(len(ciphertext)+len(authenticationTag)), NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadHeartbeat(stream net.Conn, header DProxyHeader) (DProxyHeartbeat, error) {
	if header.Type != HEARTBEAT {
		return DProxyHeartbeat{}, fmt.Errorf(ErrorUnexpectedType, HEARTBEAT, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyHeartbeat{}, err
	}

	var timestamp = binary.BigEndian.Uint64(buffer[0:8])
	return DProxyHeartbeat{header, timestamp}, nil
}

func SendHeartbeat(stream net.Conn, timestamp uint64) (int, error) {
	var buffer = make([]byte, 8)
	binary.BigEndian.PutUint64(buffer[0:8], timestamp)

	var header = DProxyHeader{1, HEARTBEAT, 8, NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadHeartbeatResponse(stream net.Conn, header DProxyHeader) (DProxyHeartbeatResponse, error) {
	if header.Type != HEARTBEAT_RESPONSE {
		return DProxyHeartbeatResponse{}, fmt.Errorf(ErrorUnexpectedType, HEARTBEAT_RESPONSE, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyHeartbeatResponse{}, err
	}

	var timestampSender = binary.BigEndian.Uint64(buffer[0:8])
	var timestampReceiver = binary.BigEndian.Uint64(buffer[8:16])
	return DProxyHeartbeatResponse{header, timestampSender, timestampReceiver}, nil
}

func SendHeartbeatResponse(stream net.Conn, timestampSender uint64, timestampReceiver uint64) (int, error) {
	var buffer = make([]byte, 16)
	binary.BigEndian.PutUint64(buffer[0:8], timestampSender)
	binary.BigEndian.PutUint64(buffer[8:16], timestampReceiver)

	var header = DProxyHeader{1, HEARTBEAT_RESPONSE, 16, NO_ERROR}
	return stream.Write(serializePacket(header, buffer))
}

func ReadError(stream net.Conn, header DProxyHeader) (DProxyErrorPacket, error) {
	if header.Type != ERROR {
		return DProxyErrorPacket{}, fmt.Errorf(ErrorUnexpectedType, ERROR, header.Type)
	}

	buffer, err := netutil.ReadExactly(stream, int(header.Length))
	if err != nil {
		return DProxyErrorPacket{}, err
	}

	messageLength := binary.BigEndian.Uint16(buffer[0:2])
	message := string(buffer[2 : 2+messageLength])

	return DProxyErrorPacket{header, message}, nil
}

func SendError(stream net.Conn, errorCode DProxyError, message string) (int, error) {
	var buffer = make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(buffer[0:2], uint16(len(message)))
	copy(buffer[2:], message)

	var header = DProxyHeader{1, ERROR, uint16(2 + len(message)), errorCode}
	return stream.Write(serializePacket(header, buffer))
}
