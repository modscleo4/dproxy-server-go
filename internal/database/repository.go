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

package database

import (
	"errors"
	"fmt"
	"path"
	"time"

	apperrors "dproxy-server-go/internal/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func New(dbPath string) (*Repository, error) {
	db, err := gorm.Open(sqlite.Open(path.Join(dbPath, "dproxy.db")), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return NewRepository(db), nil
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

func (r *Repository) GetClientByPublicKey(derPublicKey []byte) (*PublicKey, error) {
	var publicKey PublicKey
	if err := r.db.Preload("Client").Where("key = ?", derPublicKey).First(&publicKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &publicKey, nil
}

func (r *Repository) GetClientByID(id string) (*Client, error) {
	var client Client
	if err := r.db.Where("id = ?", id).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (r *Repository) CreatePublicKey(clientID string, derPublicKey []byte) error {
	publicKey := &PublicKey{
		Key:      derPublicKey,
		ClientId: clientID,
		Enabled:  true,
	}
	return r.db.Create(publicKey).Error
}

func (r *Repository) UpdateClientLastConnectedAt(publicKey *PublicKey) error {
	return r.db.Model(publicKey).Update("last_connected_at", time.Now()).Error
}
