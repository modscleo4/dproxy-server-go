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
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"dproxy-server-go/internal/database"
	apperrors "dproxy-server-go/internal/errors"
	"dproxy-server-go/pkg/dproxy"
)

type Server struct {
	config       *Config
	dproxyServer *dproxy.Server
	repo         *database.Repository
	logger       *slog.Logger
}

func New(config *Config) (*Server, error) {
	logger := slog.Default()

	if _, err := os.Stat(config.Server.KeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s (generate with: openssl ecparam -genkey -name prime256v1 -out private.pem)", config.Server.KeyPath)
	}

	dproxyServer, err := dproxy.NewServer(config.Server.KeyPath, config.DProxy.EncryptData)
	if err != nil {
		return nil, err
	}

	repo, err := database.New(config.Database.Path)
	if err != nil {
		return nil, err
	}

	return &Server{
		config:       config,
		dproxyServer: dproxyServer,
		repo:         repo,
		logger:       logger,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	go s.startHTTPServer(ctx)
	go s.startDProxyServer(ctx)
	go s.startSocksServer(ctx)
	go s.startHeartbeatTicker(ctx)

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		s.logger.Info("Shutdown signal received")
	case <-ctx.Done():
		s.logger.Info("Context cancelled")
	}

	return s.Shutdown()
}

func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down server...")

	err := s.repo.Close()
	if err != nil {
		s.logger.Error("Error closing database", "error", err)
	}

	s.dproxyServer.CloseAll()

	return nil
}

func (s *Server) getDProxyClient(
	username string,
	password string,
	clientPassword string,
) (*dproxy.Client, error) {
	clientDB, err := s.repo.GetClientByID(username)
	if err != nil {
		s.logger.Error("Error when getting client", "error", err)
		return nil, err
	}

	if clientDB == nil || !clientDB.Enabled || password != clientPassword {
		s.logger.Debug("Invalid credentials", "username", username, "password", password)
		return nil, apperrors.ErrInvalidCredentials
	}

	if !s.dproxyServer.IsClientConnected(username) {
		s.logger.Debug("Client not connected", "username", username)
		return nil, apperrors.ErrClientNotConnected
	}

	return s.dproxyServer.GetClient(username), nil
}
