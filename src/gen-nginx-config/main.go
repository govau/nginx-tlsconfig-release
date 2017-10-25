package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	configDir string
	credhub   *credhubClient
}

type credhubClient struct {
	ClientID      string
	ClientSecret  string
	CredHubURL    string
	UAAURL        string
	UAAClient     *http.Client
	CredHubClient *http.Client
	token         *oauthToken
}

func newCredhubClient(c *config) (*credhubClient, error) {
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

	return &credhubClient{
		UAAClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: uaaTLS}},
		CredHubClient: &http.Client{Transport: &http.Transport{TLSClientConfig: credhubTLS}},
		ClientID:      c.Refresh.ClientID,
		ClientSecret:  c.Refresh.ClientSecret,
		UAAURL:        c.Refresh.UAAURL,
		CredHubURL:    c.Refresh.CredHubURL,
	}, nil
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

	c.credhub, err = newCredhubClient(&c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (ch *credhubClient) MakeRequest(path string, params url.Values, rv interface{}) error {
	if ch.token == nil || time.Unix(ch.token.Expiry, 0).Before(time.Now().Add(5*time.Minute)) {
		r, err := http.NewRequest(http.MethodPost, ch.UAAURL+"/oauth/token", bytes.NewReader([]byte((&url.Values{
			"client_id":     {ch.ClientID},
			"client_secret": {ch.ClientSecret},
			"grant_type":    {"client_credentials"},
			"response_type": {"token"},
		}).Encode())))
		if err != nil {
			return err
		}
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := ch.UAAClient.Do(r)
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

		ch.token = &at
	}

	req, err := http.NewRequest(http.MethodGet, ch.CredHubURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+ch.token.AccessToken)

	resp, err := ch.CredHubClient.Do(req)
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

	return json.Unmarshal(contents, rv)
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

type credhubCert struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

var (
	errNoDNSFound = errors.New("no dns names found in cert")
)

func (c *config) MakeConfForCert(cert *credhubCert) (bool, string, error) {
	block, _ := pem.Decode([]byte(cert.Certificate))
	if block == nil {
		return false, "", errors.New("no cert found in pem")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return false, "", errors.New("invalid cert found in pem")
	}

	pc, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, "", err
	}

	if len(pc.DNSNames) == 0 {
		return false, "", errNoDNSFound
	}

	// We'll just hash the cert content for the filename
	hc := sha256.Sum256(block.Bytes)

	rv := false

	nameOfFile := hex.EncodeToString(hc[:])
	dirty, err := c.SaveSafe(nameOfFile+".key", []byte(strings.TrimSpace(cert.PrivateKey)+"\n"))
	if err != nil {
		return false, "", err
	}
	if dirty {
		rv = true
	}
	dirty, err = c.SaveSafe(nameOfFile+".crt", []byte(strings.TrimSpace(cert.Certificate)+"\n"+strings.TrimSpace(cert.CA)+"\n"))
	if err != nil {
		return false, "", err
	}
	if dirty {
		rv = true
	}

	return rv, fmt.Sprintf(`server {
		server_name %s;
		ssl_certificate %s/%s.crt;
		ssl_certificate_key %s/%s.key;
		%s
	}`, strings.Join(pc.DNSNames, " "), c.configDir, nameOfFile, c.configDir, nameOfFile, c.Template.Server), nil

}

func (c *config) GetServerConf() (bool, []string, error) {
	var resp struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	err := c.credhub.MakeRequest("/api/v1/data", url.Values{"path": {"/certs"}}, &resp)
	if err != nil {
		return false, nil, err
	}
	var rv []string
	retDirty := false
	for _, cred := range resp.Credentials {
		var cr struct {
			Data []struct {
				Value credhubCert `json:"value"`
			} `json:"data"`
		}
		err := c.credhub.MakeRequest("/api/v1/data", url.Values{
			"name":    {cred.Name},
			"current": {"true"},
		}, &cr)
		if err != nil {
			return false, nil, err
		}
		for _, v := range cr.Data {
			dirty, nginxConf, err := c.MakeConfForCert(&v.Value)
			switch err {
			case nil:
				rv = append(rv, nginxConf)
			case errNoDNSFound:
				log.Println("No DNS found in cert, skipping: ", cred.Name)
			default:
				return false, nil, err
			}
			if dirty {
				retDirty = true
			}
		}
	}

	return retDirty, rv, nil
}

// Returns (did we write a new file)
func (c *config) SaveSafe(name string, data []byte) (bool, error) {
	fpath := filepath.Join(c.configDir, name)

	// See if we can avoid...
	oldData, err := ioutil.ReadFile(fpath)
	if err == nil {
		if bytes.Equal(oldData, data) {
			return false, nil // all done here
		}
	}

	// Write to new file
	err = ioutil.WriteFile(fpath+".new", data, 0400)
	if err != nil {
		return false, err
	}

	// Rename over old file, which is meant to be somewhat "atomic" sometimes...
	err = os.Rename(fpath+".new", fpath)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *config) UpdateConfig(failEmpty bool) (bool, error) {
	retDirty := false

	dirty, perServer, err := c.GetServerConf()
	if err != nil {
		if failEmpty {
			err = nil
		}
		if err != nil {
			return false, err
		}
	}

	if dirty {
		retDirty = true
	}

	dirty, err = c.SaveSafe("nginx.conf", []byte(fmt.Sprintf(`%s
		events {
			%s
		}

		http {
			%s
			%s
		}`, c.Template.Global, c.Template.Events, c.Template.HTTP, strings.Join(perServer, "\n"))))
	if err != nil {
		return false, err
	}

	if dirty {
		retDirty = true
	}

	return retDirty, nil
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
			dirty, err := conf.UpdateConfig(false)
			if err == nil {
				if dirty { // only reload if we actually changed a file on disk, and fully succeeded
					err = conf.ReloadNginx()
				}
			}
			if err != nil {
				log.Println("Error updating config, will keep previous config and ignore error:", err)
			}
			time.Sleep(time.Duration(conf.Refresh.Period) * time.Second)
		}
	} else {
		// once off, just update
		_, err = conf.UpdateConfig(true)
		if err != nil {
			// this is usually ignored by the calling script
			log.Fatal("error updating config:", err)
		}
	}
}
