package credhub

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	ClientID       string   `yaml:"client_id"`
	ClientSecret   string   `yaml:"client_secret"`
	UAAURL         string   `yaml:"uaa_url"`                 // URL to access
	UAACACerts     []string `yaml:"uaa_ca_certificates"`     // CA certs for credhub host
	CredHubURL     string   `yaml:"credhub_url"`             // URL to access
	CredHubCACerts []string `yaml:"credhub_ca_certificates"` // CA certs for credhub host

	uaaClient     *http.Client
	credHubClient *http.Client
	token         *oauthToken
}

func (c *Client) Init() error {
	uaaCaCertPool := x509.NewCertPool()
	credHubCaCertPool := x509.NewCertPool()

	for _, ca := range c.UAACACerts {
		ok := uaaCaCertPool.AppendCertsFromPEM([]byte(ca))
		if !ok {
			return errors.New("AppendCertsFromPEM was not ok")
		}
	}
	for _, ca := range c.CredHubCACerts {
		ok := credHubCaCertPool.AppendCertsFromPEM([]byte(ca))
		if !ok {
			return errors.New("AppendCertsFromPEM was not ok")
		}
	}

	uaaTLS := &tls.Config{RootCAs: uaaCaCertPool}
	credhubTLS := &tls.Config{RootCAs: credHubCaCertPool}

	uaaTLS.BuildNameToCertificate()
	credhubTLS.BuildNameToCertificate()

	c.uaaClient = &http.Client{Transport: &http.Transport{TLSClientConfig: uaaTLS}}
	c.credHubClient = &http.Client{Transport: &http.Transport{TLSClientConfig: credhubTLS}}

	return nil
}

type oauthToken struct {
	AccessToken string `json:"access_token"`
	Expiry      int64  `json:"expires_in"`
}

func (ch *Client) updateToken() error {
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

		resp, err := ch.uaaClient.Do(r)
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

	return nil
}

func (ch *Client) MakeRequest(path string, params url.Values, rv interface{}) error {
	req, err := http.NewRequest(http.MethodGet, ch.CredHubURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return err
	}

	return ch.rawMakeRequest(req, rv)
}

func (ch *Client) PutRequest(path string, val, rv interface{}) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, ch.CredHubURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}

	return ch.rawMakeRequest(req, rv)
}

func (ch *Client) rawMakeRequest(req *http.Request, rv interface{}) error {
	err := ch.updateToken()
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+ch.token.AccessToken)

	resp, err := ch.credHubClient.Do(req)
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
