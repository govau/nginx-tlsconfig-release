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
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	yaml "gopkg.in/yaml.v2"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/govau/cf-common/credhub"
	"github.com/govau/cf-common/uaa"
)

type config struct {
	CredHub    credhub.Client `yaml:"credhub"`
	CertSource string         `yaml:"cert_source"` // "acme" or "self-signed"

	ACME *acmeCertSource `yaml:"acme"`

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
		InsecureCookies bool     `yaml:"insecure_cookies"`
		ExternalURL     string   `yaml:"external_url"`
		CSRFKey         string   `yaml:"csrf_key"`
		AllowedUsers    []string `yaml:"allowed_users"`
	} `yaml:"admin"`

	DaysBeforeToRenew int `yaml:"days_before"`

	NginxClient string `yaml:"nginx_credhub_actor"`
	Period      int    `yaml:"period"` // seconds between scans

	adminHostname string
	certFactory   certSource
	cookies       *sessions.CookieStore
}

type certSource interface {
	// AutoFetchCert will try to fetch a cert now for the hostname and given context (you should set this to timeout)
	AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error)

	// Source returns a name that we compare to check if the cert we have is from the right source
	Source() string
}

type selfSignedSource struct{}

func (sss *selfSignedSource) Source() string {
	return "self-signed"
}

func (sss *selfSignedSource) AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error) {
	tmpl := &x509.Certificate{
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}

type acmeCertSource struct {
	Key struct {
		PrivateKey string `yaml:"private_key"`
	} `yaml:"key"`
	URL          string `yaml:"url"`
	EmailContact string `yaml:"email"`

	acmeClient          *acme.Client
	acmeKnownRegistered bool

	challengeMutex    sync.RWMutex
	challengeResponse map[string][]byte
}

func (acs *acmeCertSource) Init() error {
	block, _ := pem.Decode([]byte(acs.Key.PrivateKey))
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

	acs.challengeResponse = make(map[string][]byte)
	return nil
}

func (acs *acmeCertSource) Source() string {
	return "acme:" + acs.URL
}

func (acs *acmeCertSource) wipeChallenges() {
	// Wipe the challenge / response map
	acs.challengeMutex.Lock()
	acs.challengeResponse = make(map[string][]byte)
	acs.challengeMutex.Unlock()
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

		defer acs.wipeChallenges()
		acs.challengeMutex.Lock()
		acs.challengeResponse[k] = []byte(v)
		acs.challengeMutex.Unlock()

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

type credhubCert struct {
	Source      string `json:"source"` // either ACME URL or "self-signed"
	Type        string `json:"type"`   // "admin" or ?
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`

	path string // set for convenience of callers, but not stored
}

type perm struct {
	Actor      string   `json:"actor"`
	Operations []string `json:"operations"`
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

	u, err := url.Parse(c.Admin.ExternalURL)
	if err != nil {
		return nil, err
	}

	c.adminHostname = u.Hostname()
	if c.adminHostname == "" {
		return nil, errors.New("admin external url must be specified")
	}

	switch c.CertSource {
	case "acme":
		err = c.ACME.Init()
		if err != nil {
			return nil, err
		}
		c.certFactory = c.ACME
	case "self-signed":
		c.certFactory = &selfSignedSource{}
	default:
		return nil, fmt.Errorf("unknown cert source: %s", c.CertSource)
	}

	if c.Period == 0 {
		return nil, errors.New("period must be specified and non-zero. should be in seconds")
	}

	c.cookies = uaa.MustCreateBasicCookieHandler(c.Admin.InsecureCookies)

	return &c, nil
}

func (c *config) getMeACert(hostname string) (string, bool, error) {
	path := pathFromHost(hostname)

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

		if pc.NotAfter.Before(time.Now().Add(24 * time.Hour * time.Duration(c.DaysBeforeToRenew))) {
			needNew = true
		}

		if chc.Source != c.certFactory.Source() {
			needNew = true
		}
	}

	if !needNew {
		return path, false, nil
	}

	err = c.renewCertNow(hostname)
	if err != nil {
		return "", false, err
	}

	return path, true, nil
}

func pathFromHost(hostname string) string {
	return "/certs/" + hex.EncodeToString([]byte(hostname))
}

func hostFromPath(path string) string {
	b, err := hex.DecodeString(path[len("/certs/"):])
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *config) renewCertNow(hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	log.Println("need a cert for:", hostname)

	der, err := c.certFactory.AutoFetchCert(ctx, pkey, hostname)
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

	certType := "cf"
	if hostname == c.adminHostname {
		certType = "admin"
	}

	err = c.saveCred(pathFromHost(hostname), &credhubCert{
		Source: c.certFactory.Source(),
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

func (c *config) periodicScan() error {
	// Next, see if our root cert exists
	_, _, err := c.getMeACert(c.adminHostname)
	if err != nil {
		return err
	}
	return nil
}

func (c *config) updateDaemon() {
	for {
		err := c.periodicScan()
		if err != nil {
			log.Println("error in periodic scan, ignoring:", err)
		}
		time.Sleep(time.Second * time.Duration(c.Period))
	}
}

func (c *config) wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	if c.ACME != nil {
		c.ACME.challengeMutex.RLock()
		v, ok := c.ACME.challengeResponse[r.URL.Path]
		c.ACME.challengeMutex.RUnlock()
		if ok {
			w.Write(v)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

type uiCert struct {
	Name          string
	Path          string
	ShowDelete    bool
	ShowRenew     bool
	DaysRemaining int
	CredHubCert   *credhubCert
}

func (c *config) add(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (c *config) flashMessage(w http.ResponseWriter, r *http.Request, m string) {
	session, _ := c.cookies.Get(r, "f")
	session.AddFlash(m)
	session.Save(r, w)
}

func (c *config) update(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	switch r.FormValue("action") {
	case "create":
		hostname := r.FormValue("host")
		if len(hostname) == 0 {
			c.flashMessage(w, r, "empty hostname")
			break
		}
		path := pathFromHost(hostname)

		// Look to see if it exists
		_, err := c.fetchCred(path)
		if err == nil {
			c.flashMessage(w, r, "already managed")
			break
		}

		err = c.saveCred(path, &credhubCert{
			Source: c.certFactory.Source(),
		})
		if err != nil {
			c.flashMessage(w, r, err.Error())
			break
		}

	case "delete":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			c.flashMessage(w, r, "cannot find cert")
			break
		}

		if hostname == c.adminHostname {
			c.flashMessage(w, r, "not allowed to delete cert for this server")
			break
		}

		err := c.deleteCred(pathFromHost(hostname))
		if err != nil {
			c.flashMessage(w, r, err.Error())
			break
		}

		c.flashMessage(w, r, "cert successfully renewed")
		break

	case "auto":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			c.flashMessage(w, r, "cannot find cert")
			break
		}

		err := c.renewCertNow(hostname)
		if err != nil {
			c.flashMessage(w, r, err.Error())
			break
		}

		c.flashMessage(w, r, "cert successfully renewed")
		break

	default:
		c.flashMessage(w, r, "unknown action")
		break
	}

	http.Redirect(w, r, "/", http.StatusFound)
	return nil, nil
}

func (c *config) deleteCred(path string) error {
	return c.CredHub.DeleteRequest("/api/v1/data", url.Values{
		"name": {path},
	})
}

func (c *config) saveCred(path string, chc *credhubCert) error {
	var ignoreMe map[string]interface{}
	return c.CredHub.PutRequest("/api/v1/data", struct {
		Name      string       `json:"name"`
		Type      string       `json:"type"`
		Overwrite bool         `json:"overwrite"`
		Value     *credhubCert `json:"value"`
		Perms     []perm       `json:"additional_permissions"`
	}{
		Name:      path,
		Type:      "json",
		Overwrite: true,
		Value:     chc,
		Perms: []perm{{
			Actor:      c.NginxClient,
			Operations: []string{"read"},
		}},
	}, &ignoreMe)
}

func (c *config) fetchAllCerts() ([]*credhubCert, error) {
	// Fetch list of certs
	var cr struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
		"path": {"/certs"},
	}, &cr)
	if err != nil {
		return nil, err
	}

	rv := make([]*credhubCert, len(cr.Credentials))
	for i, curCred := range cr.Credentials {
		rv[i], err = c.fetchCred(curCred.Name)
		if err != nil {
			return nil, err
		}
	}

	return rv, nil
}

func (c *config) fetchCred(path string) (*credhubCert, error) {
	var cr2 struct {
		Data []struct {
			//Name  string      `json:"name"`
			Value credhubCert `json:"value"`
		} `json:"data"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
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

func (c *config) home(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	// Fetch list of certs
	certs, err := c.fetchAllCerts()
	if err != nil {
		return nil, err
	}

	certsForUI := make([]uiCert, len(certs))
	for i, curCred := range certs {
		nameToShow := hostFromPath(curCred.path)
		if nameToShow == "" {
			nameToShow = "cannot decode: " + string(curCred.path)
		}

		daysRemaining := -1

		if curCred.Certificate != "" {
			block, _ := pem.Decode([]byte(curCred.Certificate))
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

			daysRemaining = int(pc.NotAfter.Sub(time.Now()).Hours() / 24)
		}

		certsForUI[i] = uiCert{
			Name:          nameToShow,
			Path:          curCred.path,
			DaysRemaining: daysRemaining,
			ShowDelete:    nameToShow != c.adminHostname,
			ShowRenew:     true,
			CredHubCert:   curCred,
		}
	}

	sort.Slice(certsForUI, func(i, j int) bool {
		return certsForUI[i].Name < certsForUI[j].Name
	})

	session, _ := c.cookies.Get(r, "f")
	flashes := session.Flashes()
	if len(flashes) != 0 {
		session.Save(r, w)
	}

	return map[string]interface{}{
		"certs":    certsForUI,
		"messages": flashes,
	}, nil
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
	r.HandleFunc("/add", c.wrapWithClient("add.html", c.add))
	r.HandleFunc("/update", c.wrapWithClient("", c.update)) // will redirect back to home

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
			Cookies: conf.cookies,
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
			AllowedUsers:   conf.Admin.AllowedUsers,
			BaseURL:        conf.Admin.ExternalURL,
			ExternalUAAURL: conf.Admin.UAA.ExternalURL,
			Logger:         log.New(os.Stderr, "", log.LstdFlags),
			ShouldIgnore: func(r *http.Request) bool {
				if r.URL.Path == "/favicon.ico" {
					return true
				}
				return false
			},
		}).Wrap(conf.createAdminHandler()))

		go conf.updateDaemon()

		// Start actual responder
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), http.HandlerFunc(conf.wellKnownHandler)))
	}
}
