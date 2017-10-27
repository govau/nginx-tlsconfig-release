package uaa

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

// OAuthGrant used to parse JSON for an access token from UAA server.
type OAuthGrant struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	JTI          string `json:"jti"`
}

// FetchAccessToken sends data to endpoint to fetch a token and returns a grant
// object.
func (c *Client) FetchAccessToken(postData url.Values) (*OAuthGrant, error) {
	err := c.init()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.GetTokenEndpoint(), bytes.NewReader([]byte(postData.Encode())))
	if err != nil {
		return nil, err
	}
	// Older versions of CF require this to be set via header, not in POST data
	// WONTFIX: we query escape these per OAuth spec. Apparently UAA does not -
	// might cause an issue if they don't fix their end.
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.uaaHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var og OAuthGrant
	err = json.NewDecoder(resp.Body).Decode(&og)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &og, nil
}

// Client will validate access tokens against a UAA instance, caching keys as
// required.
type Client struct {
	// URL is the URL to UAA, e.g. https://uaa.system.example.com.
	URL string

	// Used for authorize redirects, and issuer validation
	ExternalURL string

	ClientID     string
	ClientSecret string

	// If specified, used in instead of system CAs
	CACerts []string

	// cachedKeysMu protects cachedKeys.
	cachedKeysMu sync.RWMutex

	// cachedKeys is the public key map.
	cachedKeys map[string]*rsa.PublicKey

	initMutex     sync.Mutex
	inited        bool
	uaaHTTPClient *http.Client
}

func (c *Client) init() error {
	c.initMutex.Lock()
	defer c.initMutex.Unlock()

	if c.inited {
		return nil
	}

	if len(c.CACerts) == 0 {
		c.uaaHTTPClient = http.DefaultClient
	} else {
		uaaCaCertPool := x509.NewCertPool()
		for _, ca := range c.CACerts {
			ok := uaaCaCertPool.AppendCertsFromPEM([]byte(ca))
			if !ok {
				return errors.New("AppendCertsFromPEM was not ok")
			}
		}
		uaaTLS := &tls.Config{RootCAs: uaaCaCertPool}
		uaaTLS.BuildNameToCertificate()
		c.uaaHTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: uaaTLS}}
	}

	c.inited = true
	return nil
}

// NewClientFromAPIURL looks up, via the apiEndpoint, the correct UAA address
// and returns a client.
func NewClientFromAPIURL(apiEndpoint string) (*Client, error) {
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var m struct {
		Links struct {
			UAA struct {
				URL string `json:"href"`
			} `json:"uaa"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	u := m.Links.UAA.URL
	if u == "" {
		return nil, errors.New("no uaa URL returned")
	}

	return &Client{
		URL:         u,
		ExternalURL: u,
	}, nil
}

func (c *Client) GetAuthorizeEndpoint() string {
	return c.ExternalURL + "/oauth/authorize"
}

func (c *Client) GetTokenEndpoint() string {
	return c.URL + "/oauth/token"
}

// ExchangeBearerTokenForClientToken takes a bearer token (such as that returned
// by CF), and exchanges via the API auth flow, for an OAuthGrant for the
// specified clientID. The clientSecret here is really not a secret.
func (c *Client) ExchangeBearerTokenForClientToken(bearerLine string) (*OAuthGrant, error) {
	err := c.init()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.GetAuthorizeEndpoint(), bytes.NewReader([]byte(url.Values{
		"client_id":     {c.ClientID},
		"response_type": {"code"},
	}.Encode())))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", bearerLine)

	hc := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c.uaaHTTPClient != nil {
		hc.Transport = c.uaaHTTPClient.Transport
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, errors.New("expected 302 back from UAA")
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	authCode := u.Query().Get("code")
	if authCode == "" {
		return nil, errors.New("expected auth code back from UAA")
	}

	return c.FetchAccessToken(url.Values(map[string][]string{
		"response_type": {"token"},
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
	}))
}

// pubKeyForID returns public key for a given key ID, if we have it, else nil
// is returned.
func (c *Client) pubKeyForID(kid string) *rsa.PublicKey {
	c.cachedKeysMu.RLock()
	defer c.cachedKeysMu.RUnlock()

	if c.cachedKeys == nil {
		return nil
	}

	rv, ok := c.cachedKeys[kid]
	if !ok {
		return nil
	}

	return rv
}

// fetchAndSaveLatestKey contacts UAA to fetch latest public key, and if it
// matches the key ID requested, then return it, else an error will be returned.
func (c *Client) fetchAndSaveLatestKey(idWanted string) (*rsa.PublicKey, error) {
	err := c.init()
	if err != nil {
		return nil, err
	}

	resp, err := c.uaaHTTPClient.Get(c.URL + "/token_key")
	if err != nil {
		return nil, err
	}

	var dd struct {
		ID  string `json:"kid"`
		PEM string `json:"value"`
	}
	err = json.NewDecoder(resp.Body).Decode(&dd)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}

	pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(dd.PEM))
	if err != nil {
		return nil, err
	}

	c.cachedKeysMu.Lock()
	defer c.cachedKeysMu.Unlock()

	if c.cachedKeys == nil {
		c.cachedKeys = make(map[string]*rsa.PublicKey)
	}

	// With old versions of CF, the KID will be empty.
	// That seems OK as it'll now be empty here too.
	c.cachedKeys[dd.ID] = pk

	if dd.ID != idWanted {
		return nil, errors.New("still can't find it")
	}

	return pk, nil
}

// Find the public key to verify the JWT, and check the algorithm.
func (c *Client) cfKeyFunc(t *jwt.Token) (interface{}, error) {
	// Ensure that RS256 is used. This might seem overkill to care,
	// but since the JWT spec actually allows a None algorithm which
	// we definitely don't want, so instead we whitelist what we will allow.
	if t.Method.Alg() != "RS256" {
		return nil, errors.New("bad token9")
	}

	// Get Key ID
	kid, ok := t.Header["kid"]
	if !ok {
		// some versions of Cloud Foundry don't return a key ID - if so, let's
		// just hope for the best.
		kid = ""
	}

	kidS, ok := kid.(string)
	if !ok {
		return nil, errors.New("bad token 11")
	}

	rv := c.pubKeyForID(kidS)
	if rv != nil {
		return rv, nil
	}

	rv, err := c.fetchAndSaveLatestKey(kidS)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

// ValidateAccessToken will validate the given access token, ensure it matches
// the client ID, and return the claims reported within.
func (c *Client) ValidateAccessToken(at, expectedClientID string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(at, c.cfKeyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("bad token 1")
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("bad token 2")
	}

	if !mapClaims.VerifyIssuer(c.ExternalURL+"/oauth/token", true) {
		return nil, errors.New("bad token 3")
	}

	// Never, ever, ever, skip a client ID check (common error).
	cid, _ := mapClaims["client_id"].(string)
	if cid != expectedClientID {
		return nil, errors.New("very bad token 4")
	}

	return mapClaims, nil
}
