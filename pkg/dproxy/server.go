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

	"dproxy-server-go/pkg/dproxy/crypt"
)

type Server struct {
	PrivateKey *ecdh.PrivateKey
	lock       sync.RWMutex
	clients    map[string]*Client
	logger     *slog.Logger
}

var encryptData = true

func NewServer(privateKeyPath string, doEncryptData bool) (*Server, error) {
	privateKeyFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(privateKeyFile)
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	ecdhPrivateKey, err := (privateKey.(*ecdsa.PrivateKey)).ECDH()
	if err != nil {
		return nil, err
	}

	encryptData = doEncryptData

	return &Server{
		PrivateKey: ecdhPrivateKey,
		clients:    make(map[string]*Client),
		logger:     slog.Default().WithGroup("dproxy"),
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

func (server *Server) StartHandshake(conn net.Conn) (*DProxyHandshakeInit, error) {
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

	server.logger.Info("Incoming connection", "hello", packet.Hello)

	return &packet, nil
}

func (server *Server) DeriveSharedSecret(derPublicKey []byte) ([]byte, error) {
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

func (server *Server) AcceptConnection(client *Client) error {
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

	_, err = SendHandshakeFinalized(conn, client.Id)
	if err != nil {
		return err
	}

	server.lock.Lock()
	server.clients[client.Id] = client
	server.lock.Unlock()

	return nil
}

func (server *Server) IsClientConnected(username string) bool {
	_, ok := server.clients[username]
	return ok
}

func (server *Server) DisconnectClient(username string) {
	server.lock.Lock()
	delete(server.clients, username)
	server.lock.Unlock()
}

type ClientStats struct {
	Info         string        `json:"info"`
	Latency      time.Duration `json:"latency"`
	BytesWritten uint64        `json:"bytes_written"`
	BytesRead    uint64        `json:"bytes_read"`
}

func (server *Server) GetClientsStats() map[string][]ClientStats {
	clients := make(map[string][]ClientStats)
	for username, client := range server.clients {
		if _, ok := clients[username]; !ok {
			clients[username] = make([]ClientStats, 0, 1)
		}

		clients[username] = append(clients[username], ClientStats{
			Info:         client.hello,
			Latency:      client.latency,
			BytesWritten: client.bytesWrite,
			BytesRead:    client.bytesRead,
		})
	}

	return clients
}

func (server *Server) GetClient(username string) *Client {
	return server.clients[username]
}

func (server *Server) SendHeartbeatToClients() {
	if len(server.clients) == 0 {
		return
	}

	server.logger.Debug("Sending heartbeat to clients")

	server.lock.RLock()
	for _, client := range server.clients {
		_, err := SendHeartbeat(*client.Conn, uint64(time.Now().UTC().UnixMilli()))
		if err != nil {
			server.logger.Error("Failed to send heartbeat to client", "username", client.Id, "error", err)
		}
	}
	server.lock.RUnlock()
}

func (server *Server) CloseAll() {
	for _, client := range server.clients {
		conn := *client.Conn
		err := conn.Close()
		if err != nil {
			server.logger.Error("Error when closing client connection", "username", client.Id, "error", err)
		}
	}

	clear(server.clients)
}
