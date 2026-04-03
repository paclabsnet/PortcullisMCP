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

package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

// tlsFixtures holds an in-memory PKI for mTLS tests.
type tlsFixtures struct {
	CACertPEM []byte // trusted CA certificate
	// Guard server (signed by trusted CA, SAN: localhost / 127.0.0.1)
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	// Gate client (signed by trusted CA)
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	// Untrusted CA + client cert signed by it (for negative tests)
	UntrustedCACertPEM     []byte
	UntrustedClientCertPEM []byte
	UntrustedClientKeyPEM  []byte
}

// generateTLSFixtures creates an ephemeral in-memory PKI suitable for mTLS tests.
func generateTLSFixtures(t *testing.T) *tlsFixtures {
	t.Helper()

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "portcullis-guard"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "portcullis-gate"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	untrustedCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate untrusted CA key: %v", err)
	}
	untrustedCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "untrusted-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	untrustedCADER, err := x509.CreateCertificate(rand.Reader, untrustedCATmpl, untrustedCATmpl, &untrustedCAKey.PublicKey, untrustedCAKey)
	if err != nil {
		t.Fatalf("create untrusted CA cert: %v", err)
	}
	untrustedCACert, err := x509.ParseCertificate(untrustedCADER)
	if err != nil {
		t.Fatalf("parse untrusted CA cert: %v", err)
	}
	untrustedCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedCADER})

	untrustedClientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate untrusted client key: %v", err)
	}
	untrustedClientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "untrusted-gate"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	untrustedClientDER, err := x509.CreateCertificate(rand.Reader, untrustedClientTmpl, untrustedCACert, &untrustedClientKey.PublicKey, untrustedCAKey)
	if err != nil {
		t.Fatalf("create untrusted client cert: %v", err)
	}
	untrustedClientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedClientDER})
	untrustedClientKeyDER, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		t.Fatalf("marshal untrusted client key: %v", err)
	}
	untrustedClientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: untrustedClientKeyDER})

	return &tlsFixtures{
		CACertPEM:              caPEM,
		ServerCertPEM:          serverCertPEM,
		ServerKeyPEM:           serverKeyPEM,
		ClientCertPEM:          clientCertPEM,
		ClientKeyPEM:           clientKeyPEM,
		UntrustedCACertPEM:     untrustedCAPEM,
		UntrustedClientCertPEM: untrustedClientCertPEM,
		UntrustedClientKeyPEM:  untrustedClientKeyPEM,
	}
}

func writePEMFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
	f.Close()
	return f.Name()
}

func buildClientTLSConfig(t *testing.T, serverCAPEM, clientCertPEM, clientKeyPEM []byte) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCAPEM) {
		t.Fatal("failed to parse server CA PEM")
	}
	cfg := &tls.Config{RootCAs: pool}
	if clientCertPEM != nil {
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			t.Fatalf("load client keypair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

func TestMTLS_ValidClientCert_Accepted(t *testing.T) {
	fx := generateTLSFixtures(t)

	cfg := validBaseConfig()
	cfg.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
		Listen: "127.0.0.1:0",
		TLS: tlsutil.TLSConfig{
			Cert:     writePEMFile(t, fx.ServerCertPEM),
			Key:      writePEMFile(t, fx.ServerKeyPEM),
			ClientCA: writePEMFile(t, fx.CACertPEM),
		},
	}

	s, _ := NewServer(context.Background(), cfg)

	serverTLSCfg, err := tlsutil.BuildServerTLS(cfg.Server.Endpoints["token_api"].TLS)
	if err != nil {
		t.Fatalf("BuildServerTLS: %v", err)
	}

	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	serverURL := "https://" + ln.Addr().String()
	go func() { _ = http.Serve(ln, s.machineAuthMiddleware(s.handleHealthz)) }()
	defer ln.Close()

	clientTLSCfg := buildClientTLSConfig(t, fx.CACertPEM, fx.ClientCertPEM, fx.ClientKeyPEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSCfg}}

	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("GET with valid client cert failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMTLS_UntrustedClientCert_Rejected(t *testing.T) {
	fx := generateTLSFixtures(t)

	cfg := validBaseConfig()
	cfg.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
		Listen: "127.0.0.1:0",
		TLS: tlsutil.TLSConfig{
			Cert:     writePEMFile(t, fx.ServerCertPEM),
			Key:      writePEMFile(t, fx.ServerKeyPEM),
			ClientCA: writePEMFile(t, fx.CACertPEM),
		},
	}

	s, _ := NewServer(context.Background(), cfg)

	serverTLSCfg, err := tlsutil.BuildServerTLS(cfg.Server.Endpoints["token_api"].TLS)
	if err != nil {
		t.Fatalf("BuildServerTLS: %v", err)
	}

	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	serverURL := "https://" + ln.Addr().String()
	go func() { _ = http.Serve(ln, s.machineAuthMiddleware(s.handleHealthz)) }()
	defer ln.Close()

	clientTLSCfg := buildClientTLSConfig(t, fx.CACertPEM, fx.UntrustedClientCertPEM, fx.UntrustedClientKeyPEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSCfg}}

	_, err = client.Get(serverURL)
	if err == nil {
		t.Fatal("expected TLS handshake failure with untrusted client cert, got nil")
	}
}
