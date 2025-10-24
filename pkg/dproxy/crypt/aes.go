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

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
)

func AESGCMEncrypt(cek []byte, iv []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	var authenticationTag = make([]byte, 16)
	ciphertext := aesGcm.Seal(nil, iv, plaintext, nil)
	copy(authenticationTag, ciphertext[len(plaintext):])

	return ciphertext[0:len(plaintext)], authenticationTag, nil
}

func AESGCMDecrypt(cek []byte, iv []byte, ciphertext []byte, authenticationTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherTextAuthTag := append(ciphertext, authenticationTag...)
	plaintext, err := aesGcm.Open(nil, iv, cipherTextAuthTag, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
