package uaa

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encoding/base64"

	"encoding/gob"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// Call this a type to stop go lint errors
type ctxKey int

const (
	// We set this value in a context for wrapped requests
	KeyLoggedInUser ctxKey = iota
)

// This value is set for handlers to be able to use
type LoggedInUser struct {
	// Will be valid for at least 5 minutes
	AccessToken string

	// Email address for user as reported by CloudFoundry
	EmailAddress string

	// Access token will expire around TTL
	TTL time.Time
}

// This session data is not passed to wrapped requests
type cfSessionData struct {
	// Refresh token for the user
	RefreshToken string

	// Used for CSRF during authorization_code dance
	State string

	// URL to redirect user too after authorization_code dance
	RedirectOnLogin string
}

// Register classes that GOB needs to know about
func init() {
	gob.Register(&cfSessionData{})
	gob.Register(&LoggedInUser{})

	// Override time for JWT validation to allow for up to 10 seconds of clock skew
	// else we quite often get tokens that we don't think have been issued yet
	jwt.TimeFunc = func() time.Time {
		return time.Now().Add(10 * time.Second)
	}
}

// http.Hander which is middleware that ensure a user is logged in, and will pass a LoggedInUser to
// wrapped HTTP requests
type LoginHandler struct {
	// Non-persistent store
	Cookies *sessions.CookieStore

	// UAA validator
	UAA *Client

	// Scopes to request
	Scopes []string

	// BaseURL of ourselves for redirect URIs
	BaseURL string

	// ExternalURL for UAA
	ExternalUAAURL string

	// Written if access is denied
	DeniedContent []byte

	// If this returns true, then this request will be passed through with no further processing
	ShouldIgnore func(*http.Request) bool

	// If this returns true, then this request will look for an Authorization header instead of cookies
	AcceptAPIHeader func(*http.Request) bool

	// If set, will log debug info
	Logger *log.Logger
}

// Validates the given access token, and return the email address reported within.
func (lh *LoginHandler) validateAccessToken(at, expectedClientID string) (string, error) {
	claims, err := lh.UAA.ValidateAccessToken(at, expectedClientID)
	if err != nil {
		return "", err
	}

	email, _ := claims["email"].(string)
	if email == "" {
		return "", errors.New("email empty")
	}

	return email, nil
}

// Send post data to the token endpoint, get a token back, and validate it.
// Return emailaddress and grant object.
func (lh *LoginHandler) fetchAndValidateToken(postData url.Values) (string, *OAuthGrant, error) {
	og, err := lh.UAA.FetchAccessToken(postData)
	if err != nil {
		return "", nil, err
	}

	// Validate token, make sure it was for us
	emailAddr, err := lh.validateAccessToken(og.AccessToken, lh.UAA.ClientID)
	if err != nil {
		return "", nil, err
	}

	return emailAddr, og, nil
}

// Wrap child handler, handle OAuth for us, call child handler once logged in
func (lh *LoginHandler) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// First pass through anything that we don't do auth on
		case lh.ShouldIgnore != nil && lh.ShouldIgnore(r):
			h.ServeHTTP(w, r)
			return

		// Next handle calls that want an API header
		case lh.AcceptAPIHeader != nil && lh.AcceptAPIHeader(r):
			// Get authorization header
			bits := strings.Split(r.Header.Get("Authorization"), " ")
			if len(bits) != 2 || strings.ToLower(bits[0]) != "bearer" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			accessToken := bits[1]

			// Validate token, make sure it was for us
			emailAddr, err := lh.validateAccessToken(accessToken, lh.UAA.ClientID+"-api")
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if emailAddr == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Finally, we are good to go.
			// Add our logged in user to the request object passed to the child
			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), KeyLoggedInUser, &LoggedInUser{
				EmailAddress: emailAddr,
				AccessToken:  accessToken,
			})))
			return

		// Cookie auth
		default:
			// Ignore error on this call, as it just means we have an empty session, and that's OK
			// (since we are not persisting cookie keys, that'll happen a lot)
			liuRaw, _ := lh.Cookies.Get(r, "lui")
			osdRaw, _ := lh.Cookies.Get(r, "osd")

			liu, _ := liuRaw.Values["d"].(*LoggedInUser)
			osd, _ := osdRaw.Values["d"].(*cfSessionData)

			if liu == nil {
				liu = &LoggedInUser{}
				liuRaw.Values["d"] = liu
			}

			if osd == nil {
				osd = &cfSessionData{}
				osdRaw.Values["d"] = osd
			}

			// First check if we are trying to logout
			if r.URL.Path == "/logout" {
				delete(liuRaw.Values, "d")
				delete(osdRaw.Values, "d")

				// ignore errors trying to save
				liuRaw.Save(r, w)
				osdRaw.Save(r, w)

				// should we log out of CF as well?
				redirect := lh.BaseURL
				if r.FormValue("cf") == "1" {
					redirect = fmt.Sprintf("%s/logout.do?redirect=%s", lh.ExternalUAAURL, url.QueryEscape(redirect))
				}

				// go back to home
				http.Redirect(w, r, redirect, http.StatusFound)
				return
			}

			// Check if this is the OAuth callback
			if r.URL.Path == "/oauth2callback" {
				if len(osd.State) > 0 && osd.State == r.FormValue("state") {
					emailAddress, og, err := lh.fetchAndValidateToken(url.Values{
						"response_type": {"token"},
						"code":          {r.FormValue("code")},
						"grant_type":    {"authorization_code"},
						"scope":         {strings.Join(lh.Scopes, " ")},
						"redirect_uri":  {lh.BaseURL + "/oauth2callback"},
					})
					if err != nil {
						if lh.Logger != nil {
							lh.Logger.Println("error in oauth2callback:", err)
						}
						w.WriteHeader(http.StatusForbidden)
						if len(lh.DeniedContent) != 0 {
							w.Write(lh.DeniedContent)
						}
						return
					}
					// All is happy
					liu.EmailAddress = emailAddress
					liu.AccessToken = og.AccessToken
					liu.TTL = time.Now().Add((time.Duration(og.ExpiresIn) * time.Second) - (5 * time.Minute))

					savedRedirect := osd.RedirectOnLogin
					osd.State = ""
					osd.RedirectOnLogin = ""
					osd.RefreshToken = og.RefreshToken

					err = liuRaw.Save(r, w)
					if err != nil {
						if lh.Logger != nil {
							lh.Logger.Println("saving session:", err)
						}
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					err = osdRaw.Save(r, w)
					if err != nil {
						if lh.Logger != nil {
							lh.Logger.Println("saving session:", err)
						}
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					// We're in, go to our original destinations
					http.Redirect(w, r, savedRedirect, http.StatusFound)
					return
				}
			}

			// Check if our TTL has expired, if so, log us out
			if time.Now().After(liu.TTL) {
				liu.EmailAddress = ""
			}

			// If we are not logged in, then try to refresh a refresh token
			if liu.EmailAddress == "" {
				if osd.RefreshToken != "" {
					emailAddress, og, err := lh.fetchAndValidateToken(url.Values{
						"response_type": {"token"},
						"refresh_token": {osd.RefreshToken},
						"grant_type":    {"refresh_token"},
						"scope":         {strings.Join(lh.Scopes, " ")},
					})
					if err != nil {
						// User might have disconnected us, so don't hard fail
						if lh.Logger != nil {
							lh.Logger.Println("error refreshing token:", err)
						}
						osd.RefreshToken = "" // zero us out so we don't try again with this token
					} else {
						// All is happy
						liu.EmailAddress = emailAddress
						liu.AccessToken = og.AccessToken
						liu.TTL = time.Now().Add((time.Duration(og.ExpiresIn) * time.Second) - (5 * time.Minute))

						osd.State = ""
						osd.RedirectOnLogin = ""
						osd.RefreshToken = og.RefreshToken

						err = liuRaw.Save(r, w)
						if err != nil {
							if lh.Logger != nil {
								lh.Logger.Println("saving session:", err)
							}
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						err = osdRaw.Save(r, w)
						if err != nil {
							if lh.Logger != nil {
								lh.Logger.Println("saving session:", err)
							}
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						// We're in, go to our original destinations
						http.Redirect(w, r, r.RequestURI, http.StatusFound)
						return
					}
				}
			}

			// Finally, we are good to go.
			if liu.EmailAddress != "" {
				// Add our logged in user to the request object passed to the child
				h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), KeyLoggedInUser, liu)))
				return
			}

			// Failing every other options, go forth and re-authorize
			osd.RedirectOnLogin = r.RequestURI
			osd.State = base64.RawURLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
			err := osdRaw.Save(r, w)
			if err != nil {
				if lh.Logger != nil {
					lh.Logger.Println("saving session:", err)
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, lh.ExternalUAAURL+"/oauth/authorize?"+(&url.Values{
				"client_id":     {lh.UAA.ClientID},
				"response_type": {"code"},
				"state":         {osd.State},
				"scope":         {strings.Join(lh.Scopes, " ")},
				"redirect_uri":  {lh.BaseURL + "/oauth2callback"},
			}).Encode(), http.StatusFound)
		}
	})
}

// Create cookie handler, panic upon failure
func MustCreateBasicCookieHandler(insecure bool) *sessions.CookieStore {
	authKey := securecookie.GenerateRandomKey(64)
	if authKey == nil {
		panic("can't create key")
	}

	encryptionKey := securecookie.GenerateRandomKey(32)
	if encryptionKey == nil {
		panic("can't create key")
	}

	rv := sessions.NewCookieStore(authKey, encryptionKey)
	rv.Options.HttpOnly = true
	rv.Options.Secure = !insecure
	return rv
}
