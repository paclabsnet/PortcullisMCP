// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redisutil provides shared Redis client construction logic used by
// Keep and Guard. Gate's Redis setup omits TLS options and is not covered here.
package redisutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/redis/go-redis/v9"
)

// Config holds connection and security settings for a Redis-backed store.
// Fields map directly to the keys in operations.storage.config in YAML configs.
type Config struct {
	Addr          string `yaml:"addr"            mapstructure:"addr"`
	Password      string `yaml:"password"        mapstructure:"password"`
	DB            int    `yaml:"db"              mapstructure:"db"`
	KeyPrefix     string `yaml:"key_prefix"      mapstructure:"key_prefix"`
	TLSEnabled    bool   `yaml:"tls_enabled"     mapstructure:"tls_enabled"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" mapstructure:"tls_skip_verify"`
	TLSCACert     string `yaml:"tls_ca_cert"     mapstructure:"tls_ca_cert"`
}

// NewClient constructs and validates a Redis client from cfg.
// Returns an error if TLS configuration is invalid or the server cannot be reached.
func NewClient(ctx context.Context, cfg Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec — user-controlled; warn below
		}
		if cfg.TLSSkipVerify {
			slog.Warn("redis TLS certificate verification is disabled — do not use in production")
		}
		if cfg.TLSCACert != "" {
			pem, err := os.ReadFile(cfg.TLSCACert)
			if err != nil {
				return nil, fmt.Errorf("read redis TLS CA cert %q: %w", cfg.TLSCACert, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("parse redis TLS CA cert %q: no valid PEM blocks found", cfg.TLSCACert)
			}
			tlsCfg.RootCAs = pool
		}
		opts.TLSConfig = tlsCfg
	}

	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to redis at %q: %w", cfg.Addr, err)
	}
	return client, nil
}
