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
	"dproxy-server-go/internal/utils"
	"dproxy-server-go/pkg/dproxy"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"dproxy-server-go/pkg/socks"
	"dproxy-server-go/pkg/socks/auth"
)

func (s *Server) startSocksServer(ctx context.Context) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server.BindAddress, s.config.Server.SocksPort))
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

	s.logger.Info("SOCKS Server is running", "address", listener.Addr().String(), "port", s.config.Server.SocksPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go s.handleSocksClient(conn)
	}
}

func (s *Server) handleSocksClient(conn net.Conn) {
	s.logger.Debug("Connection from Socks", "remoteAddr", conn.RemoteAddr().String())

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			s.logger.Error("Error when closing SOCKS client connection", "error", err)
			return
		}
	}(conn)

	_, err := socks.ReadVersionIdentifier(conn)
	if err != nil {
		s.logger.Error("Error when reading version identifier", "error", err)
		return
	}

	err = socks.SendMethodSelection(conn, socks.AUTH_USERNAME_PASSWORD)
	if err != nil {
		s.logger.Error("Error when sending auth method response", "error", err)
		return
	}

	usernameAuthRequest, err := socks.ReadUsernameAuthRequest(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
			return
		}

		s.logger.Error("Error when reading auth request", "error", err)
		return
	}

	client, err := s.getDProxyClient(usernameAuthRequest.Uname, usernameAuthRequest.Passwd, s.config.Auth.HTTPPassword)
	if err != nil {
		err = socks.SendUsernameAuthReply(conn, auth.AUTH_FAILURE)
		return
	}

	err = socks.SendUsernameAuthReply(conn, auth.AUTH_SUCCESS)
	if err != nil {
		s.logger.Error("Error when sending auth success response", "error", err)
		return
	}

	request, err := socks.ReadRequest(conn)
	if err != nil {
		s.logger.Error("Error when reading request", "error", err)
		return
	}

	switch request.Cmd {
	case socks.CMD_CONNECT:
		s.handleSocksClientConnect(client, request, conn)
		return
	}

	err = socks.SendReply(conn, socks.REPLY_COMMAND_NOT_SUPPORTED, netip.IPv4Unspecified(), 0)
	if err != nil {
		s.logger.Error("Error when reading request", "error", err)
		return
	}
}

func (s *Server) handleSocksClientConnect(client *dproxy.Client, request socks.SocksRequest, conn net.Conn) {
	destination := socks.GetDestinationAsStr(request)
	connectionId, err, isTimeout := client.ConnectTo(destination, dproxy.TCP, request.DstPort, 30)
	if err != nil {
		err = socks.SendReply(conn, utils.IIF(isTimeout, socks.REPLY_TTL_EXPIRED, socks.REPLY_HOST_UNREACHABLE), netip.IPv4Unspecified(), 0)
		return
	}

	defer (func() {
		err = client.DisconnectFrom(connectionId)
		if err != nil {
			s.logger.Error("Error when disconnecting from client", "error", err)
			return
		}
	})()

	client.SetConnectionStream(connectionId, &conn)
	if !s.dproxyServer.IsClientConnected(client.Id) {
		return
	}

	bindAddr := client.GetConnectionBindAddress(connectionId)
	if bindAddr == nil {
		err = socks.SendReply(conn, socks.REPLY_HOST_UNREACHABLE, netip.IPv4Unspecified(), 0)
		if err != nil {
			s.logger.Error("Error when sending host bind address", "error", err)
		}

		return
	}

	err = socks.SendReply(conn, socks.REPLY_SUCCEEDED, bindAddr.Addr(), bindAddr.Port())
	if err != nil {
		s.logger.Error("Error when sending reply", "error", err)
		return
	}

	s.logger.Info("Socks client connected", "username", client.Id)

	for {
		buffer := make([]byte, 4096)
		bytes, err := conn.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
				s.logger.Debug("Remote connection closed", "error", err, "connectionId", connectionId)
				break
			}

			s.logger.Error("Error when reading response", "error", err)
			return
		}

		err = client.WriteData(connectionId, buffer[:bytes])
		if err != nil {
			return
		}
	}
}
