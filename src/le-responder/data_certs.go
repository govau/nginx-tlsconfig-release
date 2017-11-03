package main

import (
	"encoding/hex"
	"errors"
	"net/url"

	"github.com/govau/cf-common/credhub"
)

type certStorage interface {
	DeletePath(path string) error
	SavePath(path string, chc *credhubCert) error
	FetchCerts() ([]*credhubCert, error)
	LoadPath(path string) (*credhubCert, error)
}

type credhubCert struct {
	Source      string         `json:"source"` // as defined by type
	Type        string         `json:"type"`   // "admin" or ?
	NeedsNew    bool           `json:"needs_new"`
	CA          string         `json:"ca"`
	Certificate string         `json:"certificate"`
	PrivateKey  string         `json:"private_key"`
	Challenge   *acmeChallenge `json:"challenge"`

	path string // set for convenience of callers, but not stored
}

func pathFromHost(hostname string) string {
	return "/certs/" + hex.EncodeToString([]byte(hostname))
}

func hostFromPath(path string) string {
	if len(path) < len("/certs/") {
		return ""
	}
	b, err := hex.DecodeString(path[len("/certs/"):])
	if err != nil {
		return ""
	}
	return string(b)
}

type certStore struct {
	CredHub *credhub.Client
}

func (cs *certStore) DeletePath(path string) error {
	return cs.CredHub.DeleteRequest("/api/v1/data", url.Values{
		"name": {path},
	})
}

func (cs *certStore) SavePath(path string, chc *credhubCert) error {
	var ignoreMe map[string]interface{}
	return cs.CredHub.PutRequest("/api/v1/data", struct {
		Name      string       `json:"name"`
		Type      string       `json:"type"`
		Overwrite bool         `json:"overwrite"`
		Value     *credhubCert `json:"value"`
	}{
		Name:      path,
		Type:      "json",
		Overwrite: true,
		Value:     chc,
	}, &ignoreMe)
}

func (cs *certStore) FetchCerts() ([]*credhubCert, error) {
	// Fetch list of certs
	var cr struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	err := cs.CredHub.MakeRequest("/api/v1/data", url.Values{
		"path": {"/certs"},
	}, &cr)
	if err != nil {
		return nil, err
	}

	rv := make([]*credhubCert, len(cr.Credentials))
	for i, curCred := range cr.Credentials {
		rv[i], err = cs.LoadPath(curCred.Name)
		if err != nil {
			return nil, err
		}
	}

	return rv, nil
}

func (cs *certStore) LoadPath(path string) (*credhubCert, error) {
	var cr2 struct {
		Data []struct {
			Value credhubCert `json:"value"`
		} `json:"data"`
	}
	err := cs.CredHub.MakeRequest("/api/v1/data", url.Values{
		"name":    {path},
		"current": {"true"},
	}, &cr2)
	if err != nil {
		return nil, err
	}

	if len(cr2.Data) != 1 {
		return nil, errors.New("bad data from credhub")
	}

	rv := cr2.Data[0].Value
	rv.path = path

	return &rv, nil
}
