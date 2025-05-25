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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"dproxy-server-go/dproxy"
)

var logger = slog.Default().WithGroup("main")
var db *gorm.DB

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

	go StartHTTPServer(&server, args.Address, args.HttpPort)
	go StartDProxyServer(&server, args.Address, args.TcpPort)
	go StartHeartbeatTicker(&server)

	<-sc
	logger.Info("Shutting down")
}

func getServerPublicKey(server *dproxy.Server, w http.ResponseWriter, _ *http.Request) {
	derPublicKey, err := x509.MarshalPKIXPublicKey(server.PrivateKey.PublicKey())
	if err != nil {
		logger.Error("Error when encoding PEM block", "error", err)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
	err = pem.Encode(
		w, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derPublicKey,
		},
	)
	if err != nil {
		logger.Error("Error when encoding PEM block", "error", err)
		return
	}
}

func uploadClientPublicKey(server *dproxy.Server, w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(
		r.Header.Get("Authorization")[7:], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return server.PrivateKey, nil
		},
	)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientId, err := token.Claims.GetSubject()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Header.Get("Content-Type") != "application/x-pem-file" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	clientDb, err := GetClientFromId(db, clientId)
	if err != nil {
		logger.Error("Error when getting client", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if clientDb == nil {
		logger.Warn("Client not found", "username", clientId)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !clientDb.Enabled {
		logger.Warn("Client not enabled", "username", clientId)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	derPublicKey := make([]byte, 0)
	_, err = r.Body.Read(derPublicKey)
	if err != nil {
		logger.Error("Error when reading request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = UploadClientPublicKey(db, clientDb, derPublicKey)
	if err != nil {
		logger.Error("Error when uploading client public key", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusCreated)
}

func handleHttpsTunnel(server *dproxy.Server, client *dproxy.Client, w http.ResponseWriter, r *http.Request) error {
	// HTTPS Proxy
	uri, err := url.Parse(fmt.Sprintf("https:%s", r.URL.String()))
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	destination := uri.Hostname()
	port := dproxy.IntOr(uri.Port(), 443)
	connectionId, err := dproxy.ConnectTo(client, destination, uint16(port), 30)
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}

	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	logger.Debug("Tunnel established")
	dproxy.SetConnectionStream(client, connectionId, &clientConn)
	go func() {
		for {
			if !dproxy.IsClientConnected(server, client.Id) {
				break
			}

			buffer := make([]byte, 32768)
			bytesRead, err := clientConn.Read(buffer)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("HTTP Client disconnected", "username", client.Id)
				break
			} else if err != nil {
				logger.Error("Error when reading the HTTP connection", "error", err)
				break
			}

			err = dproxy.WriteData(client, connectionId, buffer[:bytesRead])
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("HTTP Client disconnected", "username", client.Id)
				break
			}
		}

		err := dproxy.DisconnectFrom(client, connectionId)
		if err != nil {
			logger.Error("Error when disconnecting from destination", "error", err)
		}

		err = clientConn.Close()
		if err != nil {
			logger.Error("Error when closing http connection", "error", err)
		}
	}()

	return nil
}

func handleHttpTunnel(server *dproxy.Server, client *dproxy.Client, w http.ResponseWriter, r *http.Request) error {
	// HTTP Proxy
	uri, err := url.Parse(r.URL.String())
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	destination := uri.Hostname()
	port := dproxy.IntOr(uri.Port(), 80)
	path := uri.Path
	connectionId, err := dproxy.ConnectTo(client, destination, uint16(port), 30)
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}

	err = dproxy.WriteData(client, connectionId, []byte(MountHttpData(r, path)))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	logger.Debug("Tunnel established")
	dproxy.SetConnectionStream(client, connectionId, &clientConn)
	go func() {
		for {
			if !dproxy.IsClientConnected(server, client.Id) {
				break
			}

			buffer := make([]byte, 32768)
			bytesRead, err := clientConn.Read(buffer)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("HTTP Client disconnected", "username", client.Id)
				break
			} else if err != nil {
				logger.Error("Error when reading the HTTP connection", "error", err)
				break
			}

			err = dproxy.WriteData(client, connectionId, buffer[:bytesRead])
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("HTTP Client disconnected", "username", client.Id)
				break
			}
		}

		err := dproxy.DisconnectFrom(client, connectionId)
		if err != nil {
			logger.Error("Error when disconnecting from destination", "error", err)
		}

		err = clientConn.Close()
		if err != nil {
			logger.Error("Error when closing connection", "error", err)
		}
	}()

	return nil
}

func StartHTTPServer(server *dproxy.Server, bindAddress string, port uint16) {
	proxyHandler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.Path == "/key-exchange" {
				getServerPublicKey(server, w, r)
				return
			} else if r.Method == "POST" && r.URL.Path == "/key-exchange" {
				uploadClientPublicKey(server, w, r)
				return
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
			}

			r.Header.Set("Authorization", originalAuth)

			clientDB, err := GetClientFromId(db, username)
			if err != nil {
				logger.Error("Error when getting client", "error", err)
				w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			if !clientDB.Enabled || password != "__SUPER_SECRET_PASSWORD__" {
				logger.Debug("Invalid credentials", "username", username, "password", password)
				w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
				w.WriteHeader(http.StatusProxyAuthRequired)
			}

			if !dproxy.IsClientConnected(server, username) {
				logger.Debug("Client not connected", "username", username)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			client := dproxy.GetClient(server, username)

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

	if err := httpServer.ListenAndServe(); err != nil {
		logger.Error("Error when starting HTTP server", "error", err)
		return
	}
}

func StartDProxyServer(server *dproxy.Server, bindAddress string, port uint16) {
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
		// Accept incoming connections
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		// Handle client connection in a goroutine
		go handleClient(conn, server)
	}
}

func handleClient(conn net.Conn, server *dproxy.Server) {
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

	for {
		err := dproxy.ReadClientData(&client)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Info("Client disconnected", "username", publicKeyDb.Client.Id)
				dproxy.DisconnectClient(server, publicKeyDb.Client.Id)
				return
			}

			logger.Error("Error when reading client data", "error", err)
		}
	}
}

func StartHeartbeatTicker(server *dproxy.Server) {
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
