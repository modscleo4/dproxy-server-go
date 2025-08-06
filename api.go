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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"dproxy-server-go/dproxy"
)

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

func getCientsStats(server *dproxy.Server, w http.ResponseWriter, _ *http.Request) {
	clients := dproxy.GetClientsStats(server)
	b, err := json.Marshal(clients)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		return
	}
}
