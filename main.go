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

package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"dproxy-server-go/dproxy"
	"dproxy-server-go/socks"
	"dproxy-server-go/socks/auth"
)

var logger = slog.Default().WithGroup("main")
var db *gorm.DB

var InvalidCredentialsError = fmt.Errorf("invalid credentials")
var NotConnectedError = fmt.Errorf("client not connected")

func main() {
	args, err := ParseArgs()
	if err != nil {
		log.Fatal(err)
	}

	slog.SetLogLoggerLevel(args.LogLevel)

	server, err := dproxy.InitServer(args.KeyPath)
	if err != nil {
		log.Fatal(err)
	}

	db, err = gorm.Open(sqlite.Open(args.DbPath), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	err = MigrateDatabase(db)
	if err != nil {
		log.Fatal(err)
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)

	go startHTTPServer(&server, args.Address, args.HttpPort, args.HttpPassword)
	go startDProxyServer(&server, args.Address, args.TcpPort)
	go startSocksServer(&server, args.Address, args.SocksPort, args.HttpPassword)
	go startHeartbeatTicker(&server)

	<-sc
	logger.Info("Shutting down")
}

func startHTTPServer(server *dproxy.Server, bindAddress string, port uint16, httpPassword string) {
	proxyHandler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.Path == "/key-exchange" {
				getServerPublicKey(server, w, r)
				return
			} else if r.Method == "POST" && r.URL.Path == "/key-exchange" {
				uploadClientPublicKey(server, w, r)
				return
			} else if r.Method == "GET" && r.URL.Path == "/stats" {
				getCientsStats(server, w, r)
			}

			if r.Method != "CONNECT" &&
				!strings.HasPrefix(r.URL.String(), "http://") &&
				!strings.HasPrefix(r.URL.String(), "ws://") {
				return
			}

			logger.Debug("Received request", "method", r.Method, "url", r.URL.String())

			originalAuth := r.Header.Get("Authorization")
			r.Header.Set("Authorization", r.Header.Get("Proxy-Authorization"))
			username, password, ok := r.BasicAuth()
			if !ok {
				logger.Debug("No basic credentials provided")
				w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			r.Header.Set("Authorization", originalAuth)

			client, err := getDProxyClient(server, username, password, httpPassword)
			if err != nil {
				w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
				if errors.Is(err, InvalidCredentialsError) {
					w.WriteHeader(http.StatusProxyAuthRequired)
				} else if errors.Is(err, NotConnectedError) {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					w.WriteHeader(http.StatusProxyAuthRequired)
				}

				return
			}

			if r.Method == "CONNECT" {
				err = handleHttpsTunnel(server, client, w, r)
				if err != nil {
					logger.Error("Error when handling HTTPS tunnel", "error", err)
				}
			} else {
				err = handleHttpTunnel(server, client, w, r)
				if err != nil {
					logger.Error("Error when handling HTTP tunnel", "error", err)
				}
			}
		},
	)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", bindAddress, port),
		Handler: proxyHandler,
	}

	slog.Debug("Starting HTTP server", "address", httpServer.Addr, "port", port, "bindAddress", bindAddress)
	if err := httpServer.ListenAndServe(); err != nil {
		logger.Error("Error when starting HTTP server", "error", err)
		return
	}
}

func startDProxyServer(server *dproxy.Server, bindAddress string, port uint16) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddress, port))
	if err != nil {
		logger.Error("Error when listening for connections", "error", err)
		return
	}

	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			logger.Error("Error when closing listener", "error", err)
			os.Exit(1)
		}
	}(listener)

	logger.Info("DproxyServer is running", "address", listener.Addr().String(), "port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go handleDProxyClient(conn, server)
	}
}

func handleDProxyClient(conn net.Conn, server *dproxy.Server) {
	logger.Debug("Connection from DproxyClient", "remoteAddr", conn.RemoteAddr().String())

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			logger.Error("Error when closing client connection", "error", err)
		}
	}(conn)

	clientPublicKey, err := dproxy.StartHandshake(conn)
	if err != nil {
		logger.Error("Error when starting handshake", "error", err)
		return
	}

	publicKeyDb, err := GetClientFromPublicKey(db, clientPublicKey)
	if err != nil {
		logger.Error("Error when authenticating client", "error", err)
		return
	}

	if publicKeyDb == nil {
		logger.Debug("Client not found", "username", clientPublicKey)
		return
	}

	if !publicKeyDb.Client.Enabled {
		logger.Debug("Client not enabled", "username", publicKeyDb.Client.Id)
		return
	}

	sharedSecret, err := dproxy.DeriveSharedSecret(clientPublicKey, server)
	if err != nil {
		logger.Error("Error when deriving shared secret", "error", err)
		return
	}

	cek, err := hkdf.Key(sha256.New, sharedSecret, nil, "", 32)
	if err != nil {
		logger.Error("Error when deriving CEK", "error", err)
		return
	}

	logger.Debug("Crypt info", "sharedSecret", hex.EncodeToString(sharedSecret), "cek", hex.EncodeToString(cek))

	client := dproxy.Client{
		Id:   publicKeyDb.Client.Id,
		CEK:  cek,
		Conn: &conn,
	}

	err = dproxy.AcceptConnection(server, &client)
	if err != nil {
		logger.Error("Error when accepting connection", "error", err)
		return
	}

	logger.Info("Client connected", "username", publicKeyDb.Client.Id)
	err = UpdateClientLastConnectedAt(db, publicKeyDb)
	if err != nil {
		logger.Error("Error when updating client last connected time", "error", err)
	}

	for {
		err := dproxy.ReadClientData(&client)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			}

			logger.Error("Error when reading client data", "error", err)
		}
	}

	logger.Info("Client disconnected", "username", publicKeyDb.Client.Id)
	dproxy.DisconnectClient(server, publicKeyDb.Client.Id)
}

func startHeartbeatTicker(server *dproxy.Server) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logger.Debug("Sending heartbeat to all clients")
			dproxy.SendHeartbeatToClients(server)
		}
	}
}

func startSocksServer(server *dproxy.Server, bindAddress string, port uint16, httpPassword string) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddress, port))
	if err != nil {
		logger.Error("Error when listening for connections", "error", err)
		return
	}

	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			logger.Error("Error when closing listener", "error", err)
			os.Exit(1)
		}
	}(listener)

	logger.Info("Socks Server is running", "address", listener.Addr().String(), "port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go handleSocksClient(conn, server, httpPassword)
	}
}

func handleSocksClient(conn net.Conn, server *dproxy.Server, httpPassword string) {
	logger.Debug("Connection from Socks", "remoteAddr", conn.RemoteAddr().String())

	_, err := socks.ReadVersionIdentifier(conn)
	if err != nil {
		logger.Error("Error when reading version identifier", "error", err)
		return
	}

	err = socks.SendMethodSelection(conn, socks.AUTH_USERNAME_PASSWORD)
	if err != nil {
		logger.Error("Error when sending auth method response", "error", err)
		return
	}

	usernameAuthRequest, err := socks.ReadUsernameAuthRequest(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
			return
		}

		logger.Error("Error when reading auth request", "error", err)
		return
	}

	client, err := getDProxyClient(server, usernameAuthRequest.Uname, usernameAuthRequest.Passwd, httpPassword)
	if err != nil {
		err = socks.SendUsernameAuthReply(conn, auth.AUTH_FAILURE)
		return
	}

	err = socks.SendUsernameAuthReply(conn, auth.AUTH_SUCCESS)
	if err != nil {
		logger.Error("Error when sending auth success response", "error", err)
		return
	}

	request, err := socks.ReadRequest(conn)
	if err != nil {
		logger.Error("Error when reading request", "error", err)
		return
	}

	if request.Cmd != socks.CMD_CONNECT {
		err = socks.SendReply(conn, socks.REPLY_COMMAND_NOT_SUPPORTED, netip.IPv4Unspecified(), 0)
	}

	destination := socks.GetDestinationAsStr(request)
	connectionId, err := dproxy.ConnectTo(client, destination, request.DstPort, 30)
	if err != nil {
		err = socks.SendReply(conn, socks.REPLY_TTL_EXPIRED, netip.IPv4Unspecified(), 0)
		return
	}

	defer (func() {
		err = dproxy.DisconnectFrom(client, connectionId)
		if err != nil {
			logger.Error("Error when disconnecting from client", "error", err)
			return
		}
	})()

	dproxy.SetConnectionStream(client, connectionId, &conn)
	if !dproxy.IsClientConnected(server, usernameAuthRequest.Uname) {
		return
	}

	bindAddr := dproxy.GetConnectionBindAddress(client, connectionId)
	if bindAddr == nil {
		err = socks.SendReply(conn, socks.REPLY_HOST_UNREACHABLE, netip.IPv4Unspecified(), 0)
		if err != nil {
			logger.Error("Error when sending host bind address", "error", err)
		}

		return
	}

	err = socks.SendReply(conn, socks.REPLY_SUCCEEDED, *bindAddr, request.DstPort)
	if err != nil {
		logger.Error("Error when sending reply", "error", err)
		return
	}

	logger.Info("Socks client connected", "username", usernameAuthRequest.Uname)

	for {
		buffer := make([]byte, 4096)
		bytes, err := conn.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			}

			logger.Error("Error when reading response", "error", err)
			return
		}

		err = dproxy.WriteData(client, connectionId, buffer[:bytes])
		if err != nil {
			return
		}
	}
}

func getDProxyClient(
	server *dproxy.Server,
	username string,
	password string,
	clientPassword string,
) (*dproxy.Client, error) {
	clientDB, err := GetClientFromId(db, username)
	if err != nil {
		logger.Error("Error when getting client", "error", err)
		return nil, err
	}

	if clientDB == nil || !clientDB.Enabled || password != clientPassword {
		logger.Debug("Invalid credentials", "username", username, "password", password)
		return nil, InvalidCredentialsError
	}

	if !dproxy.IsClientConnected(server, username) {
		logger.Debug("Client not connected", "username", username)
		return nil, NotConnectedError
	}

	return dproxy.GetClient(server, username), nil
}
