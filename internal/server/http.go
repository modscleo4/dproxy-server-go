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
	"net/http"

	apphttp "dproxy-server-go/internal/http"
)

func (s *Server) startHTTPServer(ctx context.Context) {
	proxyHandler := apphttp.NewHandler(s.dproxyServer, s.repo, s.config.Auth.HTTPPassword)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.config.Server.BindAddress, s.config.Server.HTTPPort),
		Handler: proxyHandler,
	}

	slog.Debug("Starting HTTP server", "address", httpServer.Addr, "port", s.config.Server.HTTPPort, "bindAddress", s.config.Server.BindAddress)
	if err := httpServer.ListenAndServe(); err != nil {
		s.logger.Error("Error when starting HTTP server", "error", err)
		return
	}
}
