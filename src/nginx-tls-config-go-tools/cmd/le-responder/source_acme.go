package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"

	"golang.org/x/crypto/acme"
)

type responder interface {
	SetChallengeValue(k string, v []byte) error
	ClearChallengeValue(k string)
}

type acmeCertSource struct {
	PrivateKey   string
	URL          string
	EmailContact string

	responderServer     responder
	acmeClient          *acme.Client
	acmeKnownRegistered bool
}

func (acs *acmeCertSource) Init() error {
	block, _ := pem.Decode([]byte(acs.PrivateKey))
	if block == nil {
		return errors.New("no private key found in pem")
	}
	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return errors.New("invalid private key found in pem for acme")
	}

	acmeKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	acs.acmeClient = &acme.Client{
		Key:          acmeKey,
		DirectoryURL: acs.URL,
	}

	return nil
}

func (acs *acmeCertSource) AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error) {
	if !acs.acmeKnownRegistered {
		log.Println("Always try to register on startup, who cares if we already have...")
		_, err := acs.acmeClient.Register(ctx, &acme.Account{
			Contact: []string{"mailto:" + acs.EmailContact},
		}, acme.AcceptTOS)
		if err != nil {
			log.Println("Error registering with LE - we've likely already done so, so ignoring:", err)
		}
	}

	log.Println("try to authorize...")
	authz, err := acs.acmeClient.Authorize(ctx, hostname)
	if err != nil {
		return nil, err
	}

	if authz.Status == acme.StatusValid {
		log.Println("already valid!")
	} else {
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, errors.New("no supported challenge type found")
		}

		k := acs.acmeClient.HTTP01ChallengePath(chal.Token)
		v, err := acs.acmeClient.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, err
		}

		defer acs.responderServer.ClearChallengeValue(k)
		acs.responderServer.SetChallengeValue(k, []byte(v))

		log.Println("accepting http challenge...")

		_, err = acs.acmeClient.Accept(ctx, chal)
		if err != nil {
			return nil, err
		}

		log.Println("waiting authorization...")
		_, err = acs.acmeClient.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, err
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}, pkey)
	if err != nil {
		return nil, err
	}

	log.Println("creating cert...")
	der, _, err := acs.acmeClient.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, err
	}

	// Serialize it
	if len(der) == 0 {
		return nil, errors.New("no certs returned")
	}

	return der, nil
}
