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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"dproxy-server-go/dproxy"
)

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
			buffer := make([]byte, 32768)
			bytesRead, err := clientConn.Read(buffer)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("HTTPS Client disconnected", "username", client.Id)
				break
			} else if err != nil {
				logger.Error("Error when reading the HTTP connection", "error", err)
				break
			}

			err = dproxy.WriteData(client, connectionId, buffer[:bytesRead])
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("DProxyClient disconnected", "username", client.Id)
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
				logger.Debug("DProxyClient disconnected", "username", client.Id)
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
