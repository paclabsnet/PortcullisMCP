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

package keep

import (
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
	"path/filepath"
	"testing"
	"time"
)

// tlsFixtures holds an in-memory PKI for mTLS tests:
//   - a trusted CA that signs the Keep server cert and the Gate client cert
//   - an untrusted CA (separate root) that signs an alternate client cert
//
// All certs have a short TTL (1 hour) — they are ephemeral test-only fixtures.
type tlsFixtures struct {
	CACertPEM []byte // trusted CA certificate
	// Keep server (signed by trusted CA, SAN: localhost / 127.0.0.1)
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

// generateTLSFixtures creates an ephemeral in-memory PKI suitable for mTLS
// handshake tests. All certificates expire in one hour.
func generateTLSFixtures(t *testing.T) *tlsFixtures {
	t.Helper()

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)

	// ---- trusted CA --------------------------------------------------------
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

	// ---- Keep server cert (signed by trusted CA) ---------------------------
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "portcullis-keep"},
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

	// ---- Gate client cert (signed by trusted CA) ---------------------------
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

	// ---- untrusted CA (separate root) --------------------------------------
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

	// ---- client cert signed by untrusted CA --------------------------------
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

// writePEMFile writes PEM data to a temp file and returns its path.
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

// startMTLSServer starts a minimal HTTPS server using the given tls.Config and
// returns its base URL. The server is shut down via t.Cleanup.
func startMTLSServer(t *testing.T, tlsCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

// ---- buildServerTLS unit tests ---------------------------------------------

func TestBuildServerTLS_ValidServerCertOnly(t *testing.T) {
	fx := generateTLSFixtures(t)
	dir := t.TempDir()

	cfg := TLSConfig{
		Cert: filepath.Join(dir, "server.crt"),
		Key:  filepath.Join(dir, "server.key"),
	}
	os.WriteFile(cfg.Cert, fx.ServerCertPEM, 0644)
	os.WriteFile(cfg.Key, fx.ServerKeyPEM, 0600)

	tlsCfg, err := buildServerTLS(cfg)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert when no client_ca set", tlsCfg.ClientAuth)
	}
}

func TestBuildServerTLS_WithClientCA_RequiresVerification(t *testing.T) {
	fx := generateTLSFixtures(t)
	dir := t.TempDir()

	cfg := TLSConfig{
		Cert:     filepath.Join(dir, "server.crt"),
		Key:      filepath.Join(dir, "server.key"),
		ClientCA: filepath.Join(dir, "ca.crt"),
	}
	os.WriteFile(cfg.Cert, fx.ServerCertPEM, 0644)
	os.WriteFile(cfg.Key, fx.ServerKeyPEM, 0600)
	os.WriteFile(cfg.ClientCA, fx.CACertPEM, 0644)

	tlsCfg, err := buildServerTLS(cfg)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("ClientCAs pool must be set when client_ca is configured")
	}
}

func TestBuildServerTLS_InvalidCertFile(t *testing.T) {
	dir := t.TempDir()
	cfg := TLSConfig{
		Cert: filepath.Join(dir, "missing.crt"),
		Key:  filepath.Join(dir, "missing.key"),
	}
	if _, err := buildServerTLS(cfg); err == nil {
		t.Fatal("expected error for missing cert file, got nil")
	}
}

func TestBuildServerTLS_InvalidClientCAFile(t *testing.T) {
	fx := generateTLSFixtures(t)
	dir := t.TempDir()

	cfg := TLSConfig{
		Cert:     filepath.Join(dir, "server.crt"),
		Key:      filepath.Join(dir, "server.key"),
		ClientCA: filepath.Join(dir, "missing-ca.crt"),
	}
	os.WriteFile(cfg.Cert, fx.ServerCertPEM, 0644)
	os.WriteFile(cfg.Key, fx.ServerKeyPEM, 0600)

	if _, err := buildServerTLS(cfg); err == nil {
		t.Fatal("expected error for missing client CA file, got nil")
	}
}

// ---- mTLS handshake tests --------------------------------------------------

// buildClientTLSConfig constructs a tls.Config for an HTTP client that:
//   - trusts serverCA to verify the server's certificate
//   - optionally presents clientCert/clientKey as the client certificate
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

	// Start Keep server with mTLS (requires client cert signed by trusted CA).
	serverTLSCfg, err := buildServerTLS(TLSConfig{
		Cert:     writePEMFile(t, fx.ServerCertPEM),
		Key:      writePEMFile(t, fx.ServerKeyPEM),
		ClientCA: writePEMFile(t, fx.CACertPEM),
	})
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	serverURL := startMTLSServer(t, serverTLSCfg)

	// Gate client presents a cert signed by the trusted CA.
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

func TestMTLS_NoClientCert_Rejected(t *testing.T) {
	fx := generateTLSFixtures(t)

	// Start Keep server requiring mTLS.
	serverTLSCfg, err := buildServerTLS(TLSConfig{
		Cert:     writePEMFile(t, fx.ServerCertPEM),
		Key:      writePEMFile(t, fx.ServerKeyPEM),
		ClientCA: writePEMFile(t, fx.CACertPEM),
	})
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	serverURL := startMTLSServer(t, serverTLSCfg)

	// Gate client presents NO client certificate.
	clientTLSCfg := buildClientTLSConfig(t, fx.CACertPEM, nil, nil)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSCfg}}

	_, err = client.Get(serverURL)
	if err == nil {
		t.Fatal("expected TLS handshake failure with no client cert, got nil")
	}
}

func TestMTLS_UntrustedClientCert_Rejected(t *testing.T) {
	fx := generateTLSFixtures(t)

	// Start Keep server: only trusts the primary CA.
	serverTLSCfg, err := buildServerTLS(TLSConfig{
		Cert:     writePEMFile(t, fx.ServerCertPEM),
		Key:      writePEMFile(t, fx.ServerKeyPEM),
		ClientCA: writePEMFile(t, fx.CACertPEM),
	})
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	serverURL := startMTLSServer(t, serverTLSCfg)

	// Gate client presents a cert signed by the untrusted CA.
	clientTLSCfg := buildClientTLSConfig(t, fx.CACertPEM, fx.UntrustedClientCertPEM, fx.UntrustedClientKeyPEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSCfg}}

	_, err = client.Get(serverURL)
	if err == nil {
		t.Fatal("expected TLS handshake failure with untrusted client cert, got nil")
	}
}
