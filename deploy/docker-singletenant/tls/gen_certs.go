//go:build ignore

// gen_certs.go generates the static mTLS certificate fixtures used by the
// Docker sandbox demo stack. Run with:
//
//	go run gen_certs.go
//
// This overwrites ca.crt, keep-server.crt, keep-server.key, guard-server.crt,
// guard-server.key, gate-client.crt, and gate-client.key in the same directory.
// Certificates are valid for 50 years so they do not need to be rotated during
// the lifetime of this project.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().AddDate(50, 0, 0) // 50-year validity

	// ---- CA ----------------------------------------------------------------
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generate CA key")

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Portcullis Demo CA"},
			CommonName:   "Portcullis Demo CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err, "create CA cert")
	caCert, err := x509.ParseCertificate(caDER)
	must(err, "parse CA cert")

	writeCert("ca.crt", caDER)
	log.Println("wrote ca.crt")

	// ---- Keep server cert --------------------------------------------------
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generate server key")

	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Portcullis Demo"},
			CommonName:   "portcullis-keep",
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", "portcullis-keep"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	must(err, "create server cert")

	writeCert("keep-server.crt", serverDER)
	writeKey("keep-server.key", serverKey)
	log.Println("wrote keep-server.crt keep-server.key")

	// ---- Guard server cert -------------------------------------------------
	guardKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generate guard server key")

	guardTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Portcullis Demo"},
			CommonName:   "portcullis-guard",
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", "portcullis-guard"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	guardDER, err := x509.CreateCertificate(rand.Reader, guardTmpl, caCert, &guardKey.PublicKey, caKey)
	must(err, "create guard server cert")

	writeCert("guard-server.crt", guardDER)
	writeKey("guard-server.key", guardKey)
	log.Println("wrote guard-server.crt guard-server.key")

	// ---- Gate client cert --------------------------------------------------
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generate client key")

	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			Organization: []string{"Portcullis Demo"},
			CommonName:   "portcullis-gate",
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	must(err, "create client cert")

	writeCert("gate-client.crt", clientDER)
	writeKey("gate-client.key", clientKey)
	log.Println("wrote gate-client.crt gate-client.key")

	log.Println("done — all certs valid until", notAfter.Format("2006-01-02"))
}

func writeCert(name string, der []byte) {
	f, err := os.Create(name)
	must(err, "create "+name)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}), "encode "+name)
}

func writeKey(name string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	must(err, "marshal "+name)
	f, err := os.Create(name)
	must(err, "create "+name)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), "encode "+name)
}

func must(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
