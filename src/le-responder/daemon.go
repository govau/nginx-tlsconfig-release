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
	"sort"
	"time"

	"github.com/govau/cf-common/credhub"
)

type certSource interface {
	// AutoFetchCert will try to fetch a cert now for the hostname and given context (you should set this to timeout)
	AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error)

	// ManualStartChallenge will return instructions on how to proceed. We'll persist it for you
	ManualStartChallenge(ctx context.Context, hostname string) (*acmeChallenge, error)

	// CompleteChallenge and issue cert
	CompleteChallenge(ctx context.Context, pkey *rsa.PrivateKey, hostname string, chal *acmeChallenge) ([][]byte, error)

	SupportsManual() bool
}

type certRenewer interface {
	RenewCertNow(hostname, cs string) error
	CanDelete(hostname string) bool
	Sources() []string
	SourceCanManual(string) bool
	StartManualChallenge(hostname string) error
	CompleteChallenge(hostname string) error
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
	sources       []string
	observer      certObserver

	updateRequests chan bool
}

func (dc *daemonConf) Sources() []string {
	return dc.sources
}

func (dc *daemonConf) SourceCanManual(cs string) bool {
	cf, ok := dc.certFactories[cs]
	if !ok {
		return false
	}
	return cf.SupportsManual()
}

func (dc *daemonConf) Init(extAdminURL string, sm sourceMap, storage certStorage, observer certObserver, responder responder) error {
	dc.updateRequests = make(chan bool, 1000)

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
	dc.sources = nil
	for name, val := range sm {
		switch val.Type {
		case "self-signed":
			dc.certFactories[name] = &selfSignedSource{}
		case "acme":
			v := &acmeCertSource{
				EmailContact:    val.Email,
				URL:             val.URL,
				PrivateKey:      val.PrivateKey,
				responderServer: responder,
			}
			err = v.Init()
			if err != nil {
				return err
			}
			dc.certFactories[name] = v

		default:
			return errors.New("unknown cert source type")
		}

		dc.sources = append(dc.sources, name)
	}

	if len(dc.certFactories) == 0 {
		return errors.New("must specify at least one cert source")
	}

	dc.storage = storage

	sort.StringSlice(dc.sources).Sort()

	dc.observer = observer

	return nil
}

func (dc *daemonConf) updateObservers() error {
	certs, err := dc.storage.FetchCerts()
	if err != nil {
		return err
	}
	return dc.observer.CertsAreUpdated(certs)
}

func (dc *daemonConf) RunForever() {
	// Periodic scan loop, this will beed the update request queue
	go func() {
		for {
			err := dc.periodicScan()
			if err != nil {
				log.Println("error in periodic scan, ignoring:", err)
			}
			time.Sleep(time.Second * time.Duration(dc.Period))
		}
	}()

	// Write out config loop
	t := time.NewTimer(time.Second * 5)
	for {
		select {
		case <-dc.updateRequests:
			// we want an update.
			// Reset our timer to fire after a reasonable period in case new certs also come through
			if !t.Stop() {
				<-t.C
			}
			t.Reset(time.Second * 30)
		case <-t.C:
			err := dc.updateObservers()
			if err == nil {
				// don't come back for a long itme
				t.Reset(time.Hour * 24 * 365)
			} else {
				log.Printf("error updating observers, will try again soon: %s\n", err)
				dc.updateRequests <- true
			}
		}
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

		if chc.NeedsNew {
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

func (dc *daemonConf) StartManualChallenge(hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	path := pathFromHost(hostname)
	curCert, err := dc.storage.LoadPath(path)
	if err != nil {
		return err
	}

	cf, ok := dc.certFactories[curCert.Source]
	if !ok {
		return fmt.Errorf("no cert source found for: %s", curCert.Source)
	}

	chal, err := cf.ManualStartChallenge(ctx, hostname)
	if err != nil {
		return err
	}

	curCert.Challenge = chal

	err = dc.storage.SavePath(path, curCert)
	if err != nil {
		return err
	}

	return nil
}

func (dc *daemonConf) CompleteChallenge(hostname string) error {
	chd, err := dc.storage.LoadPath(pathFromHost(hostname))
	if err != nil {
		return err
	}

	if chd.Challenge == nil {
		return errors.New("challenge not set")
	}

	return dc.getCertAndSave(hostname, chd.Source, func(ctx context.Context, cf certSource, pkey *rsa.PrivateKey) ([][]byte, error) {
		return cf.CompleteChallenge(ctx, pkey, hostname, chd.Challenge)
	})
}

func (dc *daemonConf) getCertAndSave(hostname, cs string, issuer func(context.Context, certSource, *rsa.PrivateKey) ([][]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	cf, ok := dc.certFactories[cs]
	if !ok {
		return fmt.Errorf("no cert source found for: %s", cs)
	}

	der, err := issuer(ctx, cf, pkey)
	if err != nil {
		return err
	}

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

	// yo, we got a cert
	dc.updateRequests <- true

	return nil
}

func (dc *daemonConf) RenewCertNow(hostname, cs string) error {
	return dc.getCertAndSave(hostname, cs, func(ctx context.Context, cf certSource, pkey *rsa.PrivateKey) ([][]byte, error) {
		return cf.AutoFetchCert(ctx, pkey, hostname)
	})
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
