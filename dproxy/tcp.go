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
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"dproxy-server-go/dproxy/crypt"
)

type Server struct {
	PrivateKey *ecdh.PrivateKey
	lock       sync.RWMutex
	clients    map[string]*Client
}

type Client struct {
	Id          string
	CEK         []byte
	Conn        *net.Conn
	nextConnId  uint32
	lock        sync.RWMutex
	connections map[uint32]*net.Conn
	connEvents  map[uint32]chan bool
}

var logger = slog.Default().WithGroup("tcp")
var encryptData = true

func InitServer(privateKeyPath string) (Server, error) {
	privateKeyFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return Server{}, err
	}

	pemBlock, _ := pem.Decode(privateKeyFile)
	if pemBlock == nil {
		return Server{}, fmt.Errorf("invalid private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return Server{}, err
	}

	ecdhPrivateKey, err := (privateKey.(*ecdsa.PrivateKey)).ECDH()
	if err != nil {
		return Server{}, err
	}

	return Server{
		PrivateKey: ecdhPrivateKey,
		clients:    make(map[string]*Client),
	}, nil
}

func validateHeader(header *DProxyHeader, expectedType DProxyPacketType) (DProxyError, error) {
	if header.Version != 1 {
		return INVALID_VERSION, fmt.Errorf("invalid version (expected 1, got %d)", header.Version)
	}

	if header.Type != expectedType {
		return INVALID_PACKET_TYPE, fmt.Errorf("invalid packet type (expected %d, got %d)", expectedType, header.Type)
	}

	return NO_ERROR, nil
}

func StartHandshake(conn net.Conn) ([]byte, error) {
	header, err := GetPacketHeader(conn)
	if err != nil {
		return nil, err
	}

	if dproxyError, err := validateHeader(&header, HANDSHAKE_INIT); err != nil {
		_, err2 := SendError(conn, dproxyError, err.Error())
		if err2 != nil {
			return nil, err2
		}

		return nil, err
	}

	packet, err := ReadHandshakeInit(conn, header)
	if err != nil {
		return nil, err
	}

	if packet.DERPublicKey == nil || len(packet.DERPublicKey) == 0 {
		_, err := SendError(conn, INVALID_HANDSHAKE_INFO, "Invalid public key")
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("invalid public key")
	}

	return packet.DERPublicKey, nil
}

func DeriveSharedSecret(derPublicKey []byte, server *Server) ([]byte, error) {
	publicKey, err := x509.ParsePKIXPublicKey(derPublicKey)
	if err != nil {
		return nil, err
	}

	ecdhPublicKey, err := publicKey.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := server.PrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return sharedSecret, err
	}

	return sharedSecret, nil
}

func AcceptConnection(server *Server, client *Client) error {
	conn := *client.Conn

	iv, err := RandomBytes(12)
	if err != nil {
		return err
	}

	plaintext, err := RandomBytes(1024)
	if err != nil {
		return err
	}

	ciphertext, authenticationTag, err := crypt.AESGCMEncrypt(client.CEK, iv, plaintext)
	if err != nil {
		return err
	}

	_, err = SendHandshakeResponse(conn, iv, ciphertext, authenticationTag)
	if err != nil {
		return err
	}

	header, err := GetPacketHeader(conn)
	if err != nil {
		return err
	}

	if dproxyError, err := validateHeader(&header, HANDSHAKE_FINAL); err != nil {
		_, err2 := SendError(conn, dproxyError, err.Error())
		if err2 != nil {
			return err2
		}

		return err
	}

	packet, err := ReadHandshakeFinal(conn, header)
	if err != nil {
		return err
	}

	if packet.Plaintext == nil || len(packet.Plaintext) == 0 {
		_, err := SendError(conn, HANDSHAKE_FAILED, "Invalid handshake final packet")
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid handshake final packet")
	}

	if !bytes.Equal(packet.Plaintext, plaintext) {
		_, err := SendError(conn, HANDSHAKE_FAILED, "Invalid handshake final packet")
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid handshake final packet")
	}

	_, err = SendHandshakeFinalized(conn)
	if err != nil {
		return err
	}

	client.nextConnId = 1
	client.connections = make(map[uint32]*net.Conn)
	client.connEvents = make(map[uint32]chan bool)
	server.lock.Lock()
	server.clients[client.Id] = client
	server.lock.Unlock()

	return nil
}

func ReadClientData(client *Client) error {
	conn := *client.Conn

	header, err := GetPacketHeader(conn)
	if err != nil {
		return err
	}

	if header.Version != 1 {
		_, err := SendError(conn, INVALID_VERSION, "This server only supports version 1")
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid version")
	}

	switch header.Type {
	case CONNECTED:
		packet, err := ReadConnected(conn, header)
		if err != nil {
			return err
		}

		logger.Debug("Connection established", "connectionId", packet.ConnectionId)
		client.connEvents[packet.ConnectionId] <- true
	case DISCONNECTED:
		packet, err := ReadDisconnected(conn, header)
		if err != nil {
			return err
		}

		logger.Debug("Connection closed", "connectionId", packet.ConnectionId)
		client.lock.Lock()
		delete(client.connections, packet.ConnectionId)
		delete(client.connEvents, packet.ConnectionId)
		client.lock.Unlock()
	case DATA:
		packet, err := ReadData(conn, header)
		if err != nil {
			return err
		}

		if packet.ConnectionId == 0 {
			return fmt.Errorf("invalid connection id")
		}

		client.lock.RLock()
		tcpConn, ok := client.connections[packet.ConnectionId]
		client.lock.RUnlock()
		if !ok {
			return fmt.Errorf("invalid connection id %d", packet.ConnectionId)
		}

		logger.Debug("Received bytes from connection", "length", len(packet.Data), "connectionId", packet.ConnectionId)
		_, err = (*tcpConn).Write(packet.Data)
		if err != nil {
			return err
		}
	case ENCRYPTED_DATA:
		packet, err := ReadEncryptedData(conn, header)
		if err != nil {
			return err
		}

		if packet.ConnectionId == 0 {
			return fmt.Errorf("invalid connection id")
		}

		client.lock.RLock()
		tcpConn, ok := client.connections[packet.ConnectionId]
		client.lock.RUnlock()
		if !ok {
			return fmt.Errorf("invalid connection id %d", packet.ConnectionId)
		}

		plaintext, err := crypt.AESGCMDecrypt(client.CEK, packet.IV, packet.Ciphertext, packet.AuthenticationTag)
		if err != nil {
			return err
		}

		logger.Debug("Received bytes from connection", "length", len(plaintext), "connectionId", packet.ConnectionId)
		_, err = (*tcpConn).Write(plaintext)
		if err != nil {
			return err
		}
	case HEARTBEAT:
		_, err := ReadHeartbeat(conn, header)
		if err != nil {
			return err
		}

		_, err = SendHeartbeatResponse(conn, time.Now().UTC().UnixMilli())
		if err != nil {
			return err
		}
	case HEARTBEAT_RESPONSE:
		_, err := ReadHeartbeatResponse(conn, header)
		if err != nil {
			return err
		}
	case ERROR:
		packet, err := ReadError(conn, header)
		if err != nil {
			return err
		}

		logger.Error("Received error from client", "errorCode", packet.ErrorCode, "message", packet.Message)
		return fmt.Errorf(packet.Message)
	default:
		_, err := SendError(conn, INVALID_PACKET_TYPE, "Invalid packet type")
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid packet type")
	}

	return nil
}

func ConnectTo(client *Client, destination string, port uint16, timeout int) (uint32, error) {
	conn := *client.Conn
	connectionId := client.nextConnId
	client.nextConnId++

	logger.Debug("Connecting to remote endpoint", "address", destination, "port", port, "connectionId", connectionId)
	_, err := SendConnect(conn, connectionId, destination, port)
	if err != nil {
		return 0, err
	}

	logger.Debug("Waiting for connection to be established", "connectionId", connectionId)
	client.lock.Lock()
	client.connEvents[connectionId] = make(chan bool)
	client.lock.Unlock()

	select {
	case res := <-client.connEvents[connectionId]:
		if res == false {
			return 0, fmt.Errorf("connection failed")
		}
	case <-time.After(time.Duration(timeout) * time.Second):
		return 0, fmt.Errorf("connection %d timed out after %d seconds", connectionId, timeout)
	}

	return connectionId, nil
}

func DisconnectFrom(client *Client, connectionId uint32) error {
	conn := *client.Conn

	client.lock.Lock()
	delete(client.connections, connectionId)
	delete(client.connEvents, connectionId)
	client.lock.Unlock()

	logger.Debug("Disconnecting from connection", "connectionId", connectionId)
	_, err := SendDisconnect(conn, connectionId)
	if err != nil {
		return err
	}

	return nil
}

func WriteData(client *Client, connectionId uint32, plaintext []byte) error {
	conn := *client.Conn

	if !encryptData {
		_, err := SendData(conn, connectionId, plaintext)
		if err != nil {
			return err
		}

		return nil
	}

	iv, err := RandomBytes(12)
	if err != nil {
		return err
	}

	ciphertext, authenticationTag, err := crypt.AESGCMEncrypt(client.CEK, iv, plaintext)
	if err != nil {
		return err
	}

	logger.Debug("Sending bytes to DProxyClient", "length", len(plaintext), "connectionId", connectionId)
	_, err = SendEncryptedData(conn, connectionId, iv, ciphertext, authenticationTag)
	if err != nil {
		return err
	}

	return nil
}

func IsClientConnected(server *Server, username string) bool {
	_, ok := server.clients[username]
	return ok
}

func DisconnectClient(server *Server, username string) {
	server.lock.Lock()
	delete(server.clients, username)
	server.lock.Unlock()
}

func GetClient(server *Server, username string) *Client {
	return server.clients[username]
}

func SetConnectionStream(client *Client, connectionId uint32, conn *net.Conn) {
	client.lock.Lock()
	client.connections[connectionId] = conn
	client.lock.Unlock()
}

func SendHeartbeatToClients(server *Server) {
	if len(server.clients) == 0 {
		return
	}

	server.lock.RLock()
	for _, client := range server.clients {
		_, err := SendHeartbeat(*client.Conn, time.Now().UTC().UnixMilli())
		if err != nil {
			logger.Error("Failed to send heartbeat to client", "username", client.Id, "error", err)
		}
	}
	server.lock.RUnlock()
}
