package main

//go:generate go-bindata -o static.go data/

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	yaml "gopkg.in/yaml.v2"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/govau/cf-common/credhub"
	"github.com/govau/cf-common/uaa"
)

type config struct {
	CredHub credhub.Client `yaml:"credhub"`
	ACME    struct {
		Disable bool `yaml:"disable"`
		Key     struct {
			PrivateKey string `yaml:"private_key"`
		} `yaml:"key"`
		URL               string `yaml:"url"`
		DaysBeforeToRenew int    `yaml:"days_before"`
		EmailContact      string `yaml:"email"`
		Period            int    `yaml:"period"`
	} `yaml:"acme"`
	Port int `yaml:"port"`

	Admin struct {
		Port int `yaml:"port"`
		UAA  struct {
			ClientID     string   `yaml:"client_id"`
			ClientSecret string   `yaml:"client_secret"`
			InternalURL  string   `yaml:"internal_url"`
			ExternalURL  string   `yaml:"external_url"`
			CACerts      []string `yaml:"ca_certs"`
		} `yaml:"uaa"`
		InsecureCookies bool   `yaml:"insecure_cookies"`
		ExternalURL     string `yaml:"external_url"`
		CSRFKey         string `yaml:"csrf_key"`
	} `yaml:"admin"`

	Certificates []struct {
		Hostnames     []string `yaml:"hostnames"`
		ChallengeType string   `yaml:"challenge"`
	} `yaml:"certificates"`

	NginxClient string `yaml:"nginx_credhub_actor"`

	acmeClient          *acme.Client
	acmeKnownRegistered bool
	adminHostname       string

	challengeMutex    sync.RWMutex
	challengeResponse map[string][]byte
}

type sharedConfig struct {
	OurCert   string   `json:"admin"`
	CertPaths []string `json:"certs"`
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

func (c *config) ensureAuthorized() error {
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
			for _, dns := range wantedCert.Hostnames {
				authz, err := c.acmeClient.Authorize(context.Background(), dns)
				if err != nil {
					return err
				}
				log.Printf("Authz: %#v\n", authz)
			}
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

type perm struct {
	Actor      string   `json:"actor"`
	Operations []string `json:"operations"`
}

func (c *config) saveAccount(acc *acme.Account) error {
	var rv map[string]interface{}
	return c.CredHub.PutRequest("/api/v1/data", struct {
		Name      string        `json:"name"`
		Type      string        `json:"type"`
		Overwrite bool          `json:"overwrite"`
		Value     *acme.Account `json:"value"`
		Perms     []perm        `json:"additional_permissions"`
	}{
		Name:      "/acme/account",
		Type:      "json",
		Overwrite: true,
		Value:     acc,
	}, &rv)
}

func (c *config) fetchAccount() (*acme.Account, error) {
	var cr struct {
		Data []struct {
			Value acme.Account `json:"value"`
		} `json:"data"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
		"name":    {"/acme/account"},
		"current": {"true"},
	}, &cr)
	if err != nil {
		return nil, err
	}
	if len(cr.Data) != 1 {
		return nil, errors.New("wrong number of accounts returned")
	}
	return &cr.Data[0].Value, nil
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

	if c.ACME.Period == 0 {
		return nil, errors.New("period must be specified, it should be in seconds")
	}

	u, err := url.Parse(c.Admin.ExternalURL)
	if err != nil {
		return nil, err
	}

	c.adminHostname = u.Hostname()
	if c.adminHostname == "" {
		return nil, errors.New("admin external url must be specified")
	}

	c.challengeResponse = make(map[string][]byte)

	return &c, nil
}

func (c *config) getMeACert(hostname string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	path := "/certs/" + hex.EncodeToString([]byte(c.adminHostname))

	var cr struct {
		Data []struct {
			Value credhubCert `json:"value"`
		} `json:"data"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
		"name":    {path},
		"current": {"true"},
	}, &cr)

	var chc *credhubCert
	needNew := false
	switch err {
	case nil:
		if len(cr.Data) != 1 {
			return "", false, errors.New("strange length")
		}
		chc = &cr.Data[0].Value
	case credhub.ErrCredNotFound:
		needNew = true
	default:
		return "", false, err
	}

	if chc != nil {
		block, _ := pem.Decode([]byte(chc.Certificate))
		if block == nil {
			return "", false, errors.New("no cert found in pem")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", false, errors.New("invalid cert found in pem")
		}

		pc, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", false, err
		}

		if pc.NotAfter.Before(time.Now().Add(24 * time.Hour * time.Duration(c.ACME.DaysBeforeToRenew))) {
			needNew = true
		}
	}

	if !needNew {
		return path, false, nil
	}

	log.Println("need a cert for:", hostname)

	if !c.acmeKnownRegistered {
		c.acmeKnownRegistered = true
		log.Println("Always try to register on startup, who cares if we already have...")
		_, err = c.acmeClient.Register(ctx, &acme.Account{
			Contact: []string{"mailto:" + c.ACME.EmailContact},
		}, acme.AcceptTOS)
		if err != nil {
			log.Println("Error registering with LE - we've likely already done so, so ignoring:", err)
		}
	}

	log.Println("try to authorize...")
	authz, err := c.acmeClient.Authorize(ctx, hostname)
	if err != nil {
		return "", false, err
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
			return "", false, errors.New("no supported challenge type found")
		}

		k := c.acmeClient.HTTP01ChallengePath(chal.Token)
		v, err := c.acmeClient.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return "", false, err
		}

		c.challengeMutex.Lock()
		c.challengeResponse[k] = []byte(v)
		c.challengeMutex.Unlock()

		log.Println("accepting http challenge...")

		_, err = c.acmeClient.Accept(ctx, chal)
		if err != nil {
			return "", false, err
		}

		log.Println("waiting authorization...")
		_, err = c.acmeClient.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return "", false, err
		}
	}

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", false, err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}, pkey)
	if err != nil {
		return "", false, err
	}

	log.Println("creating cert...")
	der, _, err := c.acmeClient.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return "", false, err
	}

	// Serialize it
	if len(der) == 0 {
		return "", false, errors.New("no certs returned")
	}

	log.Println("got it, saving to credhub")

	roots := ""
	for _, r := range der[1:] {
		roots += string(pem.EncodeToMemory(&pem.Block{
			Bytes: r,
			Type:  "CERTIFICATE",
		}))
	}

	var rv map[string]interface{}
	err = c.CredHub.PutRequest("/api/v1/data", struct {
		Name      string       `json:"name"`
		Type      string       `json:"type"`
		Overwrite bool         `json:"overwrite"`
		Value     *credhubCert `json:"value"`
		Perms     []perm       `json:"additional_permissions"`
	}{
		Name:      path,
		Type:      "json",
		Overwrite: true,
		Value: &credhubCert{
			CA: roots,
			Certificate: string(pem.EncodeToMemory(&pem.Block{
				Bytes: der[0],
				Type:  "CERTIFICATE",
			})),
			PrivateKey: string(pem.EncodeToMemory(&pem.Block{
				Bytes: x509.MarshalPKCS1PrivateKey(pkey),
				Type:  "RSA PRIVATE KEY",
			})),
		},
		Perms: []perm{{
			Actor:      c.NginxClient,
			Operations: []string{"read"},
		}},
	}, &rv)
	if err != nil {
		return "", false, err
	}

	return path, true, nil
}

func (c *config) periodicScan() error {
	// Wipe the challenge / response map
	c.challengeMutex.Lock()
	c.challengeResponse = make(map[string][]byte)
	c.challengeMutex.Unlock()

	// First, read the data
	var conf struct {
		Data []struct {
			Value sharedConfig `json:"value"`
		} `json:"data"`
	}

	dirty := false
	var cc *sharedConfig

	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
		"name":    {"/config"},
		"current": {"true"},
	}, &conf)
	switch err {
	case nil:
		if len(conf.Data) != 1 {
			return errors.New("invalid found")
		}
		cc = &conf.Data[0].Value
	case credhub.ErrCredNotFound:
		cc = &sharedConfig{}
		dirty = true
	default:
		return err
	}

	// Next, see if our root cert exists
	rootPath, written, err := c.getMeACert(c.adminHostname)
	if err != nil {
		return err
	}
	if written {
		cc.OurCert = rootPath
		cc.CertPaths = []string{rootPath}
		dirty = true
	}

	if dirty {
		// Write out our config record
		var rv map[string]interface{}
		err = c.CredHub.PutRequest("/api/v1/data", struct {
			Name      string        `json:"name"`
			Type      string        `json:"type"`
			Overwrite bool          `json:"overwrite"`
			Value     *sharedConfig `json:"value"`
			Perms     []perm        `json:"additional_permissions"`
		}{
			Name:      "/config",
			Type:      "json",
			Overwrite: true,
			Value:     cc,
			Perms: []perm{{
				Actor:      c.NginxClient,
				Operations: []string{"read"},
			}},
		}, &rv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *config) updateDaemon() {
	for {
		err := c.periodicScan()
		if err != nil {
			log.Println("error in periodic scan, ignoring:", err)
		}
		time.Sleep(time.Second * time.Duration(c.ACME.Period))
	}
}

func (c *config) wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	c.challengeMutex.RLock()
	v, ok := c.challengeResponse[r.URL.Path]
	c.challengeMutex.RUnlock()

	if ok {
		w.Write(v)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (c *config) home(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

// Fetch the logged in user, and create a cloudfoundry client object and pass that to the underlying real handler.
// Finally, if a template name is specified, and no error returned, execute the template with the values returned
func (c *config) wrapWithClient(tmpl string, f func(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		liu, ok := r.Context().Value(uaa.KeyLoggedInUser).(*uaa.LoggedInUser)
		if !ok {
			log.Println("bad type")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		toPass, err := f(mux.Vars(r), liu, w, r)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// If no template is desired, then stop here
		if tmpl == "" {
			return
		}

		data, err := Asset("data/" + tmpl)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		toPass["user"] = liu
		toPass[csrf.TemplateTag] = csrf.TemplateField(r)
		template.Must(template.New("orgs").Parse(string(data))).Execute(w, toPass)
	}
}

func (c *config) createAdminHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", c.wrapWithClient("index.html", c.home))

	// Wrap nearly everything with a CSRF
	var opts []csrf.Option
	if c.Admin.InsecureCookies {
		opts = append(opts, csrf.Secure(false))
	}

	// TODO, check whether cast is really the right thing here...
	return csrf.Protect([]byte(c.Admin.CSRFKey), opts...)(r)
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
		// Start admin server, we care less if this fails, so we'll get the process on the responder
		go http.ListenAndServe(fmt.Sprintf(":%d", conf.Admin.Port), (&uaa.LoginHandler{
			Cookies: uaa.MustCreateBasicCookieHandler(conf.Admin.InsecureCookies),
			UAA: &uaa.Client{
				URL:          conf.Admin.UAA.InternalURL,
				CACerts:      conf.Admin.UAA.CACerts,
				ClientID:     conf.Admin.UAA.ClientID,
				ClientSecret: conf.Admin.UAA.ClientSecret,
				ExternalURL:  conf.Admin.UAA.ExternalURL,
			},
			Scopes: []string{
				"openid",
			},
			BaseURL:        conf.Admin.ExternalURL,
			ExternalUAAURL: conf.Admin.UAA.ExternalURL,
			Logger:         log.New(os.Stderr, "", log.LstdFlags),
		}).Wrap(conf.createAdminHandler()))

		if !conf.ACME.Disable {
			go conf.updateDaemon()
		}

		// Start actual responder
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), http.HandlerFunc(conf.wellKnownHandler)))
	}
}
