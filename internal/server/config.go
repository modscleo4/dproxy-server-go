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
	"flag"
	"fmt"
	"log/slog"
	"os"
)

type Config struct {
	Database DatabaseConfig
	Server   ServerConfig
	Auth     AuthConfig
	DProxy   DProxyConfig
	Logging  LoggingConfig
}

type DatabaseConfig struct {
	Path string
}

type ServerConfig struct {
	BindAddress string
	HTTPPort    uint16
	TCPPort     uint16
	SocksPort   uint16
	KeyPath     string
}

type AuthConfig struct {
	HTTPPassword string
}

type DProxyConfig struct {
	EncryptData bool
}

type LoggingConfig struct {
	Level slog.Level
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Database
	flag.StringVar(&cfg.Database.Path, "db-path", getenvOr("DB_PATH", "./db/dproxy.db"), "SQLite database path")

	// Server
	flag.StringVar(&cfg.Server.KeyPath, "key-path", getenvOr("KEY_PATH", "./keys/private.pem"), "EC private key path")
	flag.StringVar(&cfg.Server.BindAddress, "address", "0.0.0.0", "Bind address")

	httpPort := flag.Uint("http-port", 8080, "HTTP port")
	tcpPort := flag.Uint("tcp-port", 8081, "TCP port")
	socksPort := flag.Uint("socks-port", 1080, "SOCKS port")

	// Auth
	flag.StringVar(&cfg.Auth.HTTPPassword, "http-password", getenvOr("HTTP_PASSWORD", "__SUPER_SECRET_PASSWORD__"), "HTTP Password")

	// DProxy
	flag.BoolVar(&cfg.DProxy.EncryptData, "dproxy-encrypt", true, "Enable data encryption for DProxy connections")

	// Logging
	logLevel := flag.String("log-level", "info", "Log level")

	flag.Parse()

	if err := validatePort(*httpPort); err != nil {
		return nil, fmt.Errorf("invalid http-port: %w", err)
	}

	if err := validatePort(*tcpPort); err != nil {
		return nil, fmt.Errorf("invalid tcp-port: %w", err)
	}

	if err := validatePort(*socksPort); err != nil {
		return nil, fmt.Errorf("invalid socks-port: %w", err)
	}

	cfg.Server.HTTPPort = uint16(*httpPort)
	cfg.Server.TCPPort = uint16(*tcpPort)
	cfg.Server.SocksPort = uint16(*socksPort)

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return nil, err
	}

	cfg.Logging.Level = level

	return cfg, nil
}

func validatePort(port uint) error {
	if port == 0 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func parseLogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug", "DEBUG":
		return slog.LevelDebug, nil
	case "info", "INFO":
		return slog.LevelInfo, nil
	case "warn", "WARN":
		return slog.LevelWarn, nil
	case "error", "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level: %s", level)
	}
}

func getenvOr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
