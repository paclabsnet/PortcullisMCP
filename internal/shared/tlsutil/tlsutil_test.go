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

package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyPath = filepath.Join(dir, "key.pem")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return certPath, keyPath
}

func TestBuildServerTLS(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := createTestCert(t, tmpDir)

	t.Run("basic success", func(t *testing.T) {
		cfg := TLSConfig{
			Cert: certPath,
			Key:  keyPath,
		}
		tlsCfg, err := BuildServerTLS(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
		assert.Len(t, tlsCfg.Certificates, 1)
	})

	t.Run("with client CA success", func(t *testing.T) {
		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: certPath, // use same cert as CA for simplicity
		}
		tlsCfg, err := BuildServerTLS(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
		assert.NotNil(t, tlsCfg.ClientCAs)
	})

	t.Run("missing cert error", func(t *testing.T) {
		cfg := TLSConfig{
			Cert: "non-existent",
			Key:  keyPath,
		}
		_, err := BuildServerTLS(cfg)
		assert.Error(t, err)
	})

	t.Run("invalid client CA error", func(t *testing.T) {
		invalidCA := filepath.Join(tmpDir, "invalid-ca.pem")
		os.WriteFile(invalidCA, []byte("not a certificate"), 0644)

		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: invalidCA,
		}
		_, err := BuildServerTLS(cfg)
		assert.Error(t, err)
	})

	t.Run("missing client CA error", func(t *testing.T) {
		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: "non-existent",
		}
		_, err := BuildServerTLS(cfg)
		assert.Error(t, err)
	})
}

func TestBuildServerTLSOptionalClient(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := createTestCert(t, tmpDir)

	t.Run("basic success", func(t *testing.T) {
		cfg := TLSConfig{
			Cert: certPath,
			Key:  keyPath,
		}
		tlsCfg, err := BuildServerTLSOptionalClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
	})

	t.Run("with client CA success", func(t *testing.T) {
		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: certPath,
		}
		tlsCfg, err := BuildServerTLSOptionalClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
		assert.NotNil(t, tlsCfg.ClientCAs)
	})

	t.Run("missing cert error", func(t *testing.T) {
		cfg := TLSConfig{
			Cert: "non-existent",
			Key:  keyPath,
		}
		_, err := BuildServerTLSOptionalClient(cfg)
		assert.Error(t, err)
	})

	t.Run("missing client CA error", func(t *testing.T) {
		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: "non-existent",
		}
		_, err := BuildServerTLSOptionalClient(cfg)
		assert.Error(t, err)
	})

	t.Run("invalid client CA error", func(t *testing.T) {
		invalidCA := filepath.Join(tmpDir, "invalid-ca-optional.pem")
		os.WriteFile(invalidCA, []byte("not a certificate"), 0644)

		cfg := TLSConfig{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: invalidCA,
		}
		_, err := BuildServerTLSOptionalClient(cfg)
		assert.Error(t, err)
	})
}
