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

package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

func PasswordHash(data string, salt []byte, cost int) (string, error) {
	dk, err := scrypt.Key([]byte(data), salt, 1<<cost, 8, 1, 64)
	if err != nil {
		return "", err
	}

	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	hashBase64 := base64.StdEncoding.EncodeToString(dk)
	return fmt.Sprintf("$7$%d$%s$%s", cost, saltBase64, hashBase64), nil
}

func PasswordVerify(hashData string, data string) (bool, error) {
	parts := strings.SplitN(hashData, "$", 5)
	if len(parts) != 5 {
		return false, errors.New("invalid hash format")
	}

	version, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}

	computedHash, err := PasswordHash(data, salt, version)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(hashData), []byte(computedHash)) == 0, nil
}
