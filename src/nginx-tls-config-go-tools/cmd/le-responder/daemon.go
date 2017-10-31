package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/govau/cf-common/credhub"
)

type certSource interface {
	// AutoFetchCert will try to fetch a cert now for the hostname and given context (you should set this to timeout)
	AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error)
}

type certRenewer interface {
	RenewCertNow(hostname, cs string) error
	CanDelete(hostname string) bool
}

type daemonConf struct {
	DaysBefore int `yaml:"days_before"`
	Period     int `yaml:"period"`
	Bootstrap  struct {
		Source string `yaml:"source"`
	} `yaml:"bootstrap"`

	fixedHosts []string
	storage    certStorage

	certFactories map[string]certSource
}

func (dc *daemonConf) Init(extAdminURL string, sm sourceMap, storage certStorage) error {
	if dc.Period == 0 {
		return errors.New("period must be specified and non-zero. should be in seconds")
	}
	if dc.DaysBefore == 0 {
		return errors.New("days before must be specified and non-zero. should be in days")
	}

	u, err := url.Parse(extAdminURL)
	if err != nil {
		return err
	}

	hn := u.Hostname()
	if hn == "" {
		return errors.New("admin external url must be specified")
	}

	dc.fixedHosts = []string{hn}

	dc.certFactories = make(map[string]certSource)
	for name, val := range sm {
		switch val.Type {
		case "self-signed":
			dc.certFactories[name] = &selfSignedSource{}
		case "acme":
			v := &acmeCertSource{
				EmailContact: val.Email,
				URL:          val.URL,
				PrivateKey:   val.PrivateKey,
			}
			err = v.Init()
			if err != nil {
				return err
			}
			dc.certFactories[name] = v

		default:
			return errors.New("unknown cert source type")
		}
	}

	if len(dc.certFactories) == 0 {
		return errors.New("must specify at least one cert source")
	}

	dc.storage = storage

	return nil
}

func (dc *daemonConf) RunForever() {
	for {
		err := dc.periodicScan()
		if err != nil {
			log.Println("error in periodic scan, ignoring:", err)
		}
		time.Sleep(time.Second * time.Duration(dc.Period))
	}
}

func (dc *daemonConf) renewCertIfNeeded(hostname string) error {
	path := pathFromHost(hostname)

	needNew := false

	chc, err := dc.storage.LoadPath(path)
	switch err {
	case nil:
		// all good, continue
	case credhub.ErrCredNotFound:
		needNew = true
	default:
		return err
	}

	sourceToUse := dc.Bootstrap.Source

	if chc != nil {
		sourceToUse = chc.Source

		block, _ := pem.Decode([]byte(chc.Certificate))
		if block == nil {
			return errors.New("no cert found in pem")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("invalid cert found in pem")
		}

		pc, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		if pc.NotAfter.Before(time.Now().Add(24 * time.Hour * time.Duration(dc.DaysBefore))) {
			needNew = true
		}
	}

	if !needNew {
		return nil
	}

	err = dc.RenewCertNow(hostname, sourceToUse)
	if err != nil {
		return err
	}

	return nil
}

func (dc *daemonConf) CanDelete(hostname string) bool {
	for _, fh := range dc.fixedHosts {
		if hostname == fh {
			return false
		}
	}
	return true
}

func (dc *daemonConf) RenewCertNow(hostname, cs string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	log.Println("need a cert for:", hostname)

	cf, ok := dc.certFactories[cs]
	if !ok {
		return fmt.Errorf("no cert source found for: %s", cs)
	}

	der, err := cf.AutoFetchCert(ctx, pkey, hostname)
	if err != nil {
		return err
	}

	log.Println("got it, saving to credhub")

	roots := ""
	for _, r := range der[1:] {
		roots += string(pem.EncodeToMemory(&pem.Block{
			Bytes: r,
			Type:  "CERTIFICATE",
		}))
	}

	certType := "admin"
	if dc.CanDelete(hostname) {
		certType = "user"
	}

	err = dc.storage.SavePath(pathFromHost(hostname), &credhubCert{
		Source: cs,
		CA:     roots,
		Type:   certType,
		Certificate: string(pem.EncodeToMemory(&pem.Block{
			Bytes: der[0],
			Type:  "CERTIFICATE",
		})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
			Type:  "RSA PRIVATE KEY",
		})),
	})
	if err != nil {
		return err
	}

	return nil
}

func (dc *daemonConf) periodicScan() error {
	// Next, see if our root cert exists
	for _, fh := range dc.fixedHosts {
		err := dc.renewCertIfNeeded(fh)
		if err != nil {
			return err
		}
	}
	return nil
}
