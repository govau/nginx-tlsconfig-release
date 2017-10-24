package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	NginxJob string `yaml:"nginx_job"` // name of nginx jobs
	Template struct {
		Global string `yaml:"global"` // added to global
		Events string `yaml:"events"` // added to events element
		HTTP   string `yaml:"http"`   // added to http element
		Server string `yaml:"server"` // added within each generated element
	} `yaml:"template"`
	Refresh struct {
		ClientID      string `yaml:"client_id"`
		ClientSecret  string `yaml:"client_secret"`
		UAAURL        string `yaml:"uaa_url"`                // URL to access
		UAACACert     string `yaml:"uaa_ca_certificate"`     // CA cert for credhub host
		CredHubURL    string `yaml:"credhub_url"`            // URL to access
		CredHubCACert string `yaml:"credhub_ca_certificate"` // CA cert for credhub host
		Period        int    `yaml:"period"`                 // seconds between refresh attempts
	} `yaml:"refresh"`
	lastWritten   string
	configDir     string
	uaaClient     *http.Client
	credhubClient *http.Client
	token         *oauthToken
}

type oauthToken struct {
	AccessToken string `json:"access_token"`
	Expiry      int64  `json:"expires_in"`
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
	c.configDir = filepath.Dir(configPath)

	uaaCaCertPool := x509.NewCertPool()
	credHubCaCertPool := x509.NewCertPool()

	ok := uaaCaCertPool.AppendCertsFromPEM([]byte(c.Refresh.UAACACert))
	if !ok {
		return nil, errors.New("AppendCertsFromPEM was not ok")
	}
	ok = credHubCaCertPool.AppendCertsFromPEM([]byte(c.Refresh.CredHubCACert))
	if !ok {
		return nil, errors.New("AppendCertsFromPEM was not ok")
	}

	uaaTLS := &tls.Config{RootCAs: uaaCaCertPool}
	credhubTLS := &tls.Config{RootCAs: credHubCaCertPool}

	uaaTLS.BuildNameToCertificate()
	credhubTLS.BuildNameToCertificate()

	c.uaaClient = &http.Client{Transport: &http.Transport{TLSClientConfig: uaaTLS}}
	c.credhubClient = &http.Client{Transport: &http.Transport{TLSClientConfig: credhubTLS}}

	return &c, nil
}

func (c *config) ConnectToCredhub() error {
	if c.token == nil || time.Unix(c.token.Expiry, 0).Before(time.Now().Add(5*time.Minute)) {
		r, err := http.NewRequest(http.MethodPost, c.Refresh.UAAURL+"/oauth/token", bytes.NewReader([]byte((&url.Values{
			"client_id":     {c.Refresh.ClientID},
			"client_secret": {c.Refresh.ClientSecret},
			"grant_type":    {"client_credentials"},
			"response_type": {"token"},
		}).Encode())))
		if err != nil {
			return err
		}
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.uaaClient.Do(r)
		if err != nil {
			return err
		}
		data, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("not OK response from UAA: %s", data)
		}

		var at oauthToken
		err = json.Unmarshal(data, &at)
		if err != nil {
			return err
		}

		c.token = &at
	}

	req, err := http.NewRequest(http.MethodGet, c.Refresh.CredHubURL+"/api/v1/data", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

	resp, err := c.credhubClient.Do(req)
	if err != nil {
		return err
	}
	contents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not OK response from CredHub: %s", contents)
	}

	log.Printf("%s\n", string(contents))
	return nil
}

func (c *config) ReloadNginx() error {
	content, err := ioutil.ReadFile(fmt.Sprintf("/var/vcap/sys/run/%s/nginx.pid", c.NginxJob))
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return err
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGHUP)
}

func (c *config) UpdateConfig(failEmpty bool) error {
	nginxConfPath := c.configDir + "/nginx.conf"

	var perServer []string
	err := c.ConnectToCredhub()
	if err != nil {
		if failEmpty {
			err = nil
		}
		if err != nil {
			return err
		}
	}

	newConfig := fmt.Sprintf(`%s
		events {
			%s
		}

		http {
			%s
			%s
		}`, c.Template.Global, c.Template.Events, c.Template.HTTP, strings.Join(perServer, "\n"))

	if newConfig == c.lastWritten {
		return nil
	}

	err = ioutil.WriteFile(nginxConfPath+".new", []byte(newConfig), 0400)
	if err != nil {
		return err
	}

	// Now, rename it over the old one
	err = os.Rename(nginxConfPath+".new", nginxConfPath)
	if err != nil {
		return err
	}

	c.lastWritten = newConfig
	return nil
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
		for {
			log.Println("Updating config")
			err = conf.UpdateConfig(false)
			if err == nil {
				err = conf.ReloadNginx()
			}
			if err != nil {
				log.Println("Error updating config, will keep previous config and ignore error:", err)
			}
			time.Sleep(time.Duration(conf.Refresh.Period) * time.Second)
		}
	} else {
		// once off, just update
		err = conf.UpdateConfig(true)
		if err != nil {
			// this is usually ignored by the calling script
			log.Fatal("error updating config:", err)
		}
	}
}
