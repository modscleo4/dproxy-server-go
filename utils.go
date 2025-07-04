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
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

type CLIArgs struct {
	DbPath       string
	KeyPath      string
	Address      string
	HttpPort     uint16
	TcpPort      uint16
	LogLevel     slog.Level
	HttpPassword string
}

func GetenvOr(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	return value
}

func ParseArgs() (*CLIArgs, error) {
	var args = &CLIArgs{}
	flag.StringVar(&args.DbPath, "db-path", GetenvOr("DB_PATH", "./db/dproxy.db"), "SQLite database path")
	flag.StringVar(&args.KeyPath, "key-path", GetenvOr("KEY_PATH", "./keys/private.pem"), "EC private key path")
	flag.StringVar(&args.Address, "address", "0.0.0.0", "Bind address to listen for connections")
	httpPort := flag.Uint("http-port", 8080, "Port to listen for HTTP connections")
	tcpPort := flag.Uint("tcp-port", 8081, "Port to listen for TCP (DProxy Client) connections")
	logLevelStr := flag.String("log-level", "info", "Log level")
	flag.StringVar(&args.HttpPassword, "http-password", GetenvOr("HTTP_PASSWORD", "__SUPER_SECRET_PASSWORD__"), "HTTP Password")

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

func MountHttpData(r *http.Request, path string) string {
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
