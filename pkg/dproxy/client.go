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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"dproxy-server-go/pkg/dproxy/crypt"
)

type Client struct {
	Id          string
	CEK         []byte
	Conn        *net.Conn
	bytesWrite  uint64
	bytesRead   uint64
	latency     time.Duration
	nextConnId  uint32
	lock        sync.RWMutex
	connections map[uint32]*net.Conn
	connEvents  map[uint32]chan bool
	connAddrs   map[uint32]*netip.Addr

	logger *slog.Logger
}

func NewClient(id string, cek []byte, conn *net.Conn) *Client {
	return &Client{
		Id:          id,
		CEK:         cek,
		Conn:        conn,
		nextConnId:  1,
		lock:        sync.RWMutex{},
		connections: make(map[uint32]*net.Conn),
		connEvents:  make(map[uint32]chan bool),
		connAddrs:   make(map[uint32]*netip.Addr),
		logger:      slog.Default().WithGroup("dproxy.client"),
	}
}

func (client *Client) ReadClientData() error {
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

		client.logger.Debug("Connection established", "connectionId", packet.ConnectionId)
		client.connEvents[packet.ConnectionId] <- true

		ip, err := netip.ParseAddr(packet.Address)
		if err != nil {
			return err
		}

		client.connAddrs[packet.ConnectionId] = &ip
	case DISCONNECTED:
		packet, err := ReadDisconnected(conn, header)
		if err != nil {
			return err
		}

		client.logger.Debug("Connection closed", "connectionId", packet.ConnectionId)
		client.lock.Lock()
		if channel, ok := client.connEvents[packet.ConnectionId]; ok {
			channel <- false
		}
		delete(client.connections, packet.ConnectionId)
		delete(client.connEvents, packet.ConnectionId)
		delete(client.connAddrs, packet.ConnectionId)
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

		client.logger.Debug("Received bytes from connection", "length", len(packet.Data), "connectionId", packet.ConnectionId)
		client.bytesRead += uint64(len(packet.Data))
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

		client.logger.Debug("Received bytes from connection", "length", len(plaintext), "connectionId", packet.ConnectionId)
		client.bytesRead += uint64(len(plaintext))
		_, err = (*tcpConn).Write(plaintext)
		if err != nil {
			return err
		}
	case HEARTBEAT:
		packet, err := ReadHeartbeat(conn, header)
		if err != nil {
			return err
		}

		timestamp := uint64(time.Now().UTC().UnixMilli())
		_, err = SendHeartbeatResponse(conn, packet.Timestamp, timestamp)
		if err != nil {
			return err
		}
	case HEARTBEAT_RESPONSE:
		packet, err := ReadHeartbeatResponse(conn, header)
		if err != nil {
			return err
		}

		timestamp := uint64(time.Now().UTC().UnixMilli())
		client.latency = time.Duration((timestamp-packet.TimestampSender)/2) * time.Millisecond
	case ERROR:
		packet, err := ReadError(conn, header)
		if err != nil {
			return err
		}

		client.logger.Error("Received error from client", "errorCode", packet.ErrorCode, "message", packet.Message)
		return errors.New(packet.Message)
	default:
		_, err := SendError(conn, INVALID_PACKET_TYPE, "Invalid packet type")
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid packet type")
	}

	return nil
}

func (client *Client) ConnectTo(destination string, port uint16, timeout int) (uint32, error) {
	conn := *client.Conn
	connectionId := client.nextConnId
	client.nextConnId++

	client.logger.Debug("Connecting to remote endpoint", "address", destination, "port", port, "connectionId", connectionId)
	_, err := SendConnect(conn, connectionId, destination, port)
	if err != nil {
		return 0, err
	}

	client.logger.Debug("Waiting for connection to be established", "connectionId", connectionId)
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

func (client *Client) DisconnectFrom(connectionId uint32) error {
	conn := *client.Conn

	client.lock.Lock()
	delete(client.connections, connectionId)
	delete(client.connEvents, connectionId)
	delete(client.connAddrs, connectionId)
	client.lock.Unlock()

	client.logger.Debug("Disconnecting from connection", "connectionId", connectionId)
	_, err := SendDisconnect(conn, connectionId)
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) IsConnected(connectionId uint32) bool {
	client.lock.RLock()
	_, ok := client.connections[connectionId]
	client.lock.RUnlock()

	return ok
}

func (client *Client) WriteData(connectionId uint32, plaintext []byte) error {
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

	client.logger.Debug("Sending bytes to DProxyClient", "length", len(plaintext), "connectionId", connectionId)
	_, err = SendEncryptedData(conn, connectionId, iv, ciphertext, authenticationTag)
	if err != nil {
		return err
	}

	client.bytesWrite += uint64(len(plaintext))
	return nil
}

func (client *Client) SetConnectionStream(connectionId uint32, conn *net.Conn) {
	client.lock.Lock()
	client.connections[connectionId] = conn
	client.lock.Unlock()
}

func (client *Client) GetConnectionBindAddress(connectionId uint32) *netip.Addr {
	addr, ok := client.connAddrs[connectionId]
	if !ok {
		return nil
	}

	return addr
}
