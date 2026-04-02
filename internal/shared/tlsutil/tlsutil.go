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

// Package tlsutil provides shared TLS configuration helpers used by Keep and Guard.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig holds paths to a TLS certificate, key, and optional client CA.
type TLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"` // non-empty = require mTLS from peer
}

// BuildServerTLS creates a tls.Config for an HTTPS server.
// If cfg.ClientCA is set, mTLS client certificate verification is required.
// Use BuildServerTLSOptionalClient when bearer-token clients must also be able to connect.
func BuildServerTLS(cfg TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.ClientCA != "" {
		caData, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse client CA: no valid certificates found")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

// BuildServerTLSOptionalClient creates a tls.Config for an HTTPS server where
// client certificate presentation is optional. If cfg.ClientCA is set, presented
// certificates are verified against the CA pool; connections without a client
// certificate are still allowed. Use this for listeners that support both mTLS
// and bearer-token authentication, where the application layer enforces auth.
func BuildServerTLSOptionalClient(cfg TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.ClientCA != "" {
		caData, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse client CA: no valid certificates found")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsCfg, nil
}
