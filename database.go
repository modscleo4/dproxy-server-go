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
	"time"

	"gorm.io/gorm"
)

type Client struct {
	Id        string     `json:"id" gorm:"primaryKey"`
	Enabled   bool       `json:"enabled"`
	CreatedAt *time.Time `json:"created_at" gorm:"autoCreateTime:milli"`
	UpdatedAt *time.Time `json:"updated_at" gorm:"autoUpdateTime:milli"`
}

type PublicKey struct {
	Key             []byte     `json:"key" gorm:"primaryKey"`
	ClientId        string     `json:"client_id" gorm:"index"`
	Enabled         bool       `json:"enabled"`
	LastConnectedAt *time.Time `json:"last_connected_at"`
	CreatedAt       *time.Time `json:"created_at" gorm:"autoCreateTime:milli"`
	UpdatedAt       *time.Time `json:"updated_at" gorm:"autoUpdateTime:milli"`

	Client *Client `json:"-" gorm:"foreignKey:ClientId;references:Id"`
}

func MigrateDatabase(db *gorm.DB) error {
	err := db.AutoMigrate(&Client{}, &PublicKey{})
	if err != nil {
		return err
	}

	return nil
}

func GetClientFromPublicKey(db *gorm.DB, derPublicKey []byte) (*PublicKey, error) {
	var publicKey = &PublicKey{}
	publicKey.Client = &Client{}
	res := db.Where(&PublicKey{Key: derPublicKey}).First(publicKey)
	if res.Error != nil {
		if res.Error.Error() == "record not found" {
			return nil, nil
		}

		return nil, res.Error
	}

	res = db.Where(&Client{Id: publicKey.ClientId}).First(publicKey.Client)
	if res.Error != nil {
		return nil, res.Error
	}

	return publicKey, nil
}

func GetClientFromId(db *gorm.DB, id string) (*Client, error) {
	var client = &Client{}
	res := db.Where(&Client{Id: id}).First(client)
	if res.Error != nil {
		if res.Error.Error() == "record not found" {
			return nil, nil
		}

		return nil, res.Error
	}

	return client, nil
}

func UploadClientPublicKey(db *gorm.DB, client *Client, derPublicKey []byte) error {
	var publicKey = &PublicKey{Key: derPublicKey, ClientId: client.Id, Enabled: true}
	res := db.Create(publicKey)
	if res.Error != nil {
		return res.Error
	}

	return nil
}
