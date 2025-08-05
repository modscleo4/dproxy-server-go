package main

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
