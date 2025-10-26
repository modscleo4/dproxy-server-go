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

package http

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"dproxy-server-go/internal/auth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (h *Handler) generateToken(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		GrantType    string `json:"grant_type"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		ClientId     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		h.logger.Error("Could not unmarshal JSON", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if payload.GrantType != "password" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if payload.Username == "" || payload.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := h.repo.GetUserByUsername(payload.Username)
	if err != nil {
		h.logger.Error("Invalid username", "error", err, "username", payload.Username)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if check, err := auth.PasswordVerify(user.Password, payload.Password); !check || err != nil {
		h.logger.Error("Invalid password", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "dproxy-server",
		ID:        uuid.Must(uuid.NewRandom()).String(),
		Subject:   payload.Username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	tokenString, err := token.SignedString(h.dproxyServer.PrivateKey)
	if err != nil {
		h.logger.Error("Error when signing JWT", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokenResponse := AuthTokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	b, err := json.Marshal(tokenResponse)
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

func (h *Handler) getServerPublicKey(w http.ResponseWriter, _ *http.Request) {
	derPublicKey, err := x509.MarshalPKIXPublicKey(h.dproxyServer.PrivateKey.PublicKey())
	if err != nil {
		h.logger.Error("Error when encoding PEM block", "error", err)
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
		h.logger.Error("Error when encoding PEM block", "error", err)
		return
	}
}

func (h *Handler) uploadClientPublicKey(w http.ResponseWriter, r *http.Request) {
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

			return h.dproxyServer.PrivateKey, nil
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

	clientDb, err := h.repo.GetClientByID(clientId)
	if err != nil {
		h.logger.Error("Error when getting client", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if clientDb == nil {
		h.logger.Warn("Client not found", "username", clientId)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !clientDb.Enabled {
		h.logger.Warn("Client not enabled", "username", clientId)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	derPublicKey := make([]byte, 0)
	_, err = r.Body.Read(derPublicKey)
	if err != nil {
		h.logger.Error("Error when reading request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = h.repo.CreatePublicKey(clientDb.Id, derPublicKey)
	if err != nil {
		h.logger.Error("Error when uploading client public key", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) getClientsStats(w http.ResponseWriter, _ *http.Request) {
	clients := h.dproxyServer.GetClientsStats()
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
