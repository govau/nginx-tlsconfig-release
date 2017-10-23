package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

type selfSignedSource struct{}

func (sss *selfSignedSource) AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error) {
	tmpl := &x509.Certificate{
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}

func (sss *selfSignedSource) ManualStartChallenge(ctx context.Context, hostname string) (*acmeChallenge, error) {
	return nil, errors.New("manual challenge not needed or supported for self-signed")
}

func (sss *selfSignedSource) CompleteChallenge(ctx context.Context, pkey *rsa.PrivateKey, hostname string, chal *acmeChallenge) ([][]byte, error) {
	return nil, errors.New("manual challenge not needed or supported for self-signed")
}

func (sss *selfSignedSource) SupportsManual() bool {
	return false
}
