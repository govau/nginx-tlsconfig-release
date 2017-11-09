package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync"

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

	responderServer responder

	lock                sync.Mutex
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

type acmeChallenge struct {
	Message       string          `json:"message"`
	Authorization string          `json:"authorization_uri"`
	Challenge     *acme.Challenge `json:"challenge"`
}

func newDNSChallenge(client *acme.Client, chal *acme.Challenge, hostname, authorization string) (*acmeChallenge, error) {
	val, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf(`Create DNS TXT record:
Name:  _acme-challenge.%s.
Value: %s`, hostname, val)
	return &acmeChallenge{
		Message:       msg,
		Authorization: authorization,
		Challenge:     chal,
	}, nil
}

func (ac *acmeChallenge) Instructions() string {
	return ac.Message
}

func (acs *acmeCertSource) ManualStartChallenge(ctx context.Context, hostname string) (*acmeChallenge, error) {
	acs.lock.Lock()
	defer acs.lock.Unlock()

	acs.ensureRegistered(ctx)
	authz, err := acs.acmeClient.Authorize(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if authz.Status == acme.StatusValid {
		return nil, errors.New("already authorized, no challenge needed")
	}
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return nil, errors.New("no supported challenge type found")
	}

	return newDNSChallenge(acs.acmeClient, chal, hostname, authz.URI)
}

func (acs *acmeCertSource) ensureRegistered(ctx context.Context) {
	if acs.acmeKnownRegistered {
		return
	}

	log.Println("Always try to register on startup, who cares if we already have...")
	_, err := acs.acmeClient.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + acs.EmailContact},
	}, acme.AcceptTOS)
	if err != nil {
		log.Println("Error registering with LE - we've likely already done so, so ignoring:", err)
	}
}

func (acs *acmeCertSource) SupportsManual() bool {
	return true
}

func (acs *acmeCertSource) CompleteChallenge(ctx context.Context, pkey *rsa.PrivateKey, hostname string, ac *acmeChallenge) ([][]byte, error) {
	acs.lock.Lock()
	defer acs.lock.Unlock()

	acs.ensureRegistered(ctx)

	log.Println("accepting dns challenge...")

	_, err := acs.acmeClient.Accept(ctx, ac.Challenge)
	if err != nil {
		return nil, err
	}

	log.Println("waiting authorization...")
	_, err = acs.acmeClient.WaitAuthorization(ctx, ac.Authorization)
	if err != nil {
		return nil, err
	}

	return acs.issueCert(ctx, hostname, pkey)
}

func (acs *acmeCertSource) AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error) {
	acs.lock.Lock()
	defer acs.lock.Unlock()

	acs.ensureRegistered(ctx)
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

	return acs.issueCert(ctx, hostname, pkey)
}

func (acs *acmeCertSource) issueCert(ctx context.Context, hostname string, pkey *rsa.PrivateKey) ([][]byte, error) {
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
