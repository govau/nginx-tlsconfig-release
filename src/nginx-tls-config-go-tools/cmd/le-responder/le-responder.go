package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/acme"

	yaml "gopkg.in/yaml.v2"

	"github.com/govau/cf-common/credhub"
)

type config struct {
	CredHub credhub.Client `yaml:"credhub"`
	ACME    struct {
		Key struct {
			PrivateKey string `yaml:"private_key"`
		} `yaml:"key"`
		URL               string `yaml:"url"`
		DaysBeforeToRenew int    `yaml:"days_before"`
	} `yaml:"acme"`
	Port         int `yaml:"port"`
	Certificates []struct {
		Hostnames     []string `yaml:"hostnames"`
		ChallengeType string   `yaml:"challenge"`
	} `yaml:"certificates"`

	acmeClient *acme.Client
}

type certsInCredhub map[string][]*x509.Certificate

func (cic certsInCredhub) getLongestUntilExpiry(hn string) *x509.Certificate {
	var rv *x509.Certificate
	for _, c := range cic[hn] {
		if rv == nil {
			rv = c
		} else {
			if c.NotAfter.After(rv.NotAfter) {
				rv = c
			}
		}
	}
	return rv
}

func (c *config) doThing() error {
	hostToCerts, err := c.getCertsByHostname()
	if err != nil {
		return err
	}

	targetTime := time.Now().Add(time.Hour * 24 * time.Duration(c.ACME.DaysBeforeToRenew))

	// Now make sure that all our cert objects are happy
	for _, wantedCert := range c.Certificates {
		allGood := true
		for _, hn := range wantedCert.Hostnames {
			bestCert := hostToCerts.getLongestUntilExpiry(hn)
			if bestCert == nil || bestCert.NotAfter.Before(targetTime) {
				allGood = false
			}
		}

		if !allGood {
			c.acmeClient.
		}
	}

	return nil
}

func (c *config) getCertsByHostname() (certsInCredhub, error) {
	hostToCerts := make(certsInCredhub)
	var resp struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{"path": {"/certs"}}, &resp)
	if err != nil {
		return nil, err
	}
	for _, cred := range resp.Credentials {
		var cr struct {
			Data []struct {
				Value credhubCert `json:"value"`
			} `json:"data"`
		}
		err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
			"name":    {cred.Name},
			"current": {"true"},
		}, &cr)
		if err != nil {
			return nil, err
		}
		for _, v := range cr.Data {
			block, _ := pem.Decode([]byte(v.Value.Certificate))
			if block == nil {
				return nil, errors.New("no cert found in pem")
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, errors.New("invalid cert found in pem")
			}

			pc, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			for _, dns := range pc.DNSNames {
				hostToCerts[dns] = append(hostToCerts[dns], pc)
			}
		}
	}

	return hostToCerts, nil
}

type credhubCert struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func newConf(configPath string) (*config, error) {
	if configPath == "" {
		return nil, errors.New("must specify a config path")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	err = c.CredHub.Init()
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(c.ACME.Key.PrivateKey))
	if block == nil {
		return nil, errors.New("no cert found in pem")
	}
	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return nil, errors.New("invalid private key found in pem for acme")
	}

	acmeKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	c.acmeClient = &acme.Client{
		Key:          acmeKey,
		DirectoryURL: c.ACME.URL,
	}

	return &c, nil
}

func main() {
	var configPath string
	var daemon bool

	flag.StringVar(&configPath, "config", "", "Path to config file - required")
	flag.BoolVar(&daemon, "daemon", false, "If set, run as a daemon, and reload pid each time")
	flag.Parse()

	conf, err := newConf(configPath)
	if err != nil {
		log.Fatal("error parsing config file", err)
	}

	if daemon {
		log.Println("Started daemon")
		http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// right back at you!
			r.Write(w)
		}))
	}
}
