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
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"dproxy-server-go/dproxy"
)

var logger = slog.Default().WithGroup("main")
var db *gorm.DB

type CLIArgs struct {
	DbPath   string
	KeyPath  string
	Address  string
	HttpPort uint16
	TcpPort  uint16
	LogLevel slog.Level
}

func main() {
	args, err := parseArgs()
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

	wg := sync.WaitGroup{}
	wg.Add(2)
	go StartHTTPServer(&server, args.Address, args.HttpPort, &wg)
	go StartDProxyServer(&server, args.Address, args.TcpPort, &wg)

	wg.Wait()
}

func parseArgs() (*CLIArgs, error) {
	var args = &CLIArgs{}
	flag.StringVar(&args.DbPath, "db-path", "./db/dproxy.db", "Path to the database file")
	flag.StringVar(&args.KeyPath, "key-path", "./keys/private.pem", "Path to the private key file")
	flag.StringVar(&args.Address, "address", "0.0.0.0", "Bind address to listen for connections")
	httpPort := flag.Uint("http-port", 8080, "Port to listen for HTTP connections")
	tcpPort := flag.Uint("tcp-port", 8081, "Port to listen for TCP (DProxy Client) connections")
	logLevelStr := flag.String("log-level", "info", "Log level")

	flag.Parse()
	if *httpPort <= 0 || *httpPort > 65535 {
		return nil, fmt.Errorf("invalid http port")
	}

	if *tcpPort <= 0 || *tcpPort > 65535 {
		return nil, fmt.Errorf("invalid dproxy port")
	}

	args.HttpPort = uint16(*httpPort)
	args.TcpPort = uint16(*tcpPort)

	switch *logLevelStr {
	case "debug", "DEBUG":
		args.LogLevel = slog.LevelDebug
		break
	case "info", "INFO":
		args.LogLevel = slog.LevelInfo
		break
	case "warn", "WARN":
		args.LogLevel = slog.LevelWarn
		break
	case "error", "ERROR":
		args.LogLevel = slog.LevelError
		break
	default:
		return nil, fmt.Errorf("invalid log level")
	}

	return args, nil
}

func StartHTTPServer(server *dproxy.Server, bindAddress string, port uint16, wg *sync.WaitGroup) {
	defer wg.Done()

	proxyHandler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.Path == "/key-exchange" {
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

			if r.Method != "CONNECT" && !strings.HasPrefix(
				r.URL.String(),
				"http://",
			) && !strings.HasPrefix(r.URL.String(), "ws://") {
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
				// HTTPS Proxy
				uri, err := url.Parse(fmt.Sprintf("https:%s", r.URL.String()))
				if err != nil {
					logger.Error("Error when parsing URL", "error", err)
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				destination := uri.Hostname()
				port := dproxy.IntOr(uri.Port(), 443)
				connectionId, err := dproxy.ConnectTo(client, destination, uint16(port), 30)
				if err != nil {
					logger.Error("Error when connecting to destination", "error", err)
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusGatewayTimeout)
					return
				}

				w.WriteHeader(http.StatusOK)
				hj, ok := w.(http.Hijacker)
				if !ok {
					logger.Error("HTTP Server doesn't support hijacking connection")
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				clientConn, _, err := hj.Hijack()
				if err != nil {
					logger.Error("HTTP Hijacking failed")
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusInternalServerError)
					return
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
							logger.Debug("HTTP Client disconnected", "username", username)
							break
						} else if err != nil {
							logger.Error("Error when reading the HTTP connection", "error", err)
							break
						}

						err = dproxy.WriteData(client, connectionId, buffer[:bytesRead])
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
							logger.Debug("HTTP Client disconnected", "username", username)
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
			} else {
				// HTTP Proxy
				uri, err := url.Parse(r.URL.String())
				if err != nil {
					logger.Error("Error when parsing URL", "error", err)
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusBadRequest)
				}

				destination := uri.Hostname()
				port := dproxy.IntOr(uri.Port(), 80)
				path := uri.Path
				connectionId, err := dproxy.ConnectTo(client, destination, uint16(port), 30)
				if err != nil {
					logger.Error("Error when connecting to destination", "error", err)
				}

				err = dproxy.WriteData(client, connectionId, []byte(mountHttpData(r, path)))
				if err != nil {
					logger.Error("Error when writing data to destination", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				hj, ok := w.(http.Hijacker)
				if !ok {
					logger.Error("HTTP Server doesn't support hijacking connection")
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				clientConn, _, err := hj.Hijack()
				if err != nil {
					logger.Error("HTTP Hijacking failed")
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"dproxy\"")
					w.WriteHeader(http.StatusInternalServerError)
					return
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
							logger.Debug("HTTP Client disconnected", "username", username)
							break
						} else if err != nil {
							logger.Error("Error when reading the HTTP connection", "error", err)
							break
						}

						err = dproxy.WriteData(client, connectionId, buffer[:bytesRead])
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
							logger.Debug("HTTP Client disconnected", "username", username)
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
			}
		},
	)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", bindAddress, port), proxyHandler); err != nil {
		logger.Error("Error when starting HTTP server", "error", err)
		return
	}
}

func StartDProxyServer(server *dproxy.Server, bindAddress string, port uint16, wg *sync.WaitGroup) {
	defer wg.Done()

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

func mountHttpData(r *http.Request, path string) string {
	data := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, path)
	for k, v := range r.Header {
		if k == "Proxy-Authorization" || k == "Proxy-Connection" {
			continue
		}

		if k == "Connection" {
			v = []string{"close"}
		}

		data += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
	}

	data += "\r\n"
	return data
}
