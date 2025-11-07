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

package server

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"dproxy-server-go/pkg/dproxy"
)

func (s *Server) startDProxyServer(ctx context.Context) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server.BindAddress, s.config.Server.TCPPort))
	if err != nil {
		s.logger.Error("Error when listening for connections", "error", err)
		return
	}

	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			s.logger.Error("Error when closing listener", "error", err)
			os.Exit(1)
		}
	}(listener)

	s.logger.Info("DproxyServer is running", "address", listener.Addr().String(), "port", s.config.Server.TCPPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go s.handleDProxyClient(conn)
	}
}

func (s *Server) handleDProxyClient(conn net.Conn) {
	s.logger.Debug("Connection from DproxyClient", "remoteAddr", conn.RemoteAddr().String())

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			s.logger.Error("Error when closing client connection", "error", err)
		}
	}(conn)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		fmt.Println("Not a TCP connection, cannot disable Nagle's algorithm.")
		return
	}

	// Set TCP_NODELAY to true
	err := tcpConn.SetNoDelay(true)
	if err != nil {
		fmt.Println("Error setting TCP_NODELAY:", err)
		return
	}

	clientPublicKey, err := s.dproxyServer.StartHandshake(conn)
	if err != nil {
		s.logger.Error("Error when starting handshake", "error", err)
		return
	}

	publicKeyDb, err := s.repo.GetClientByPublicKey(clientPublicKey)
	if err != nil {
		s.logger.Error("Error when authenticating client", "error", err)
		return
	}

	if publicKeyDb == nil {
		s.logger.Debug("Client not found", "publicKey", clientPublicKey)
		return
	}

	if !publicKeyDb.Client.Enabled {
		s.logger.Debug("Client not enabled", "username", publicKeyDb.Client.Id)
		return
	}

	sharedSecret, err := s.dproxyServer.DeriveSharedSecret(clientPublicKey)
	if err != nil {
		s.logger.Error("Error when deriving shared secret", "error", err)
		return
	}

	cek, err := hkdf.Key(sha256.New, sharedSecret, nil, "", 32)
	if err != nil {
		s.logger.Error("Error when deriving CEK", "error", err)
		return
	}

	s.logger.Debug("Crypt info", "sharedSecret", hex.EncodeToString(sharedSecret), "cek", hex.EncodeToString(cek))

	client := dproxy.NewClient(publicKeyDb.Client.Id, cek, &conn)

	err = s.dproxyServer.AcceptConnection(client)
	if err != nil {
		s.logger.Error("Error when accepting connection", "error", err)
		return
	}

	s.logger.Info("Client connected", "username", publicKeyDb.Client.Id)
	err = s.repo.UpdateClientLastConnectedAt(publicKeyDb)
	if err != nil {
		s.logger.Error("Error when updating client last connected time", "error", err)
	}

	for {
		err := client.ReadClientData()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			}

			s.logger.Error("Error when reading client data", "error", err)
		}
	}

	s.logger.Info("Client disconnected", "username", publicKeyDb.Client.Id)
	s.dproxyServer.DisconnectClient(publicKeyDb.Client.Id)
}

func (s *Server) startHeartbeatTicker(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.dproxyServer.SendHeartbeatToClients()
		}
	}
}
