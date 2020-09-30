// Copyright 2016, 2020 Tamás Gulácsi
//
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package oauth2client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// Azure AD v2 endpoint
var AzureV2Endpoint = oauth2.Endpoint{
	AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
	TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
}

var Log = func(keyvals ...interface{}) error { log.Println(keyvals...); return nil }

var _ = oauth2.TokenSource((*authenticator)(nil))

// NewTokenSource returns a new token source, saved in fileName.
func NewTokenSource(conf *oauth2.Config, fileName string, tlsFiles ...string) oauth2.TokenSource {
	a := authenticator{Config: conf, FileName: fileName}
	if len(tlsFiles) == 2 && tlsFiles[0] != "" && tlsFiles[1] != "" {
		a.TLSCertFile, a.TLSKeyFile = tlsFiles[0], tlsFiles[1]
	}
	return oauth2.ReuseTokenSource(nil, &a)
}

type authenticator struct {
	*oauth2.Config
	FileName                string
	TLSCertFile, TLSKeyFile string
}

func (a *authenticator) Token() (*oauth2.Token, error) {
	m := make(map[string]*oauth2.Token)
	key := a.ClientID + ":" + strings.Join(a.Scopes, "\t")
	var tok *oauth2.Token
	if fh, err := os.Open(a.FileName); err == nil {
		err = json.NewDecoder(fh).Decode(&m)
		fh.Close()
		if err != nil {
			Log("file", a.FileName, "error", err)
		} else {
			if tok = m[key]; tok.Valid() {
				return tok, nil
			}
			Log("msg", "Token is invalid", "token", tok)
		}
	}
	tok, err := Authenticate(a.Config, a.TLSCertFile, a.TLSKeyFile)
	if err != nil {
		return tok, err
	}
	m[key] = tok
	fh, err := os.OpenFile(a.FileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		Log("msg", "save token", "file", a.FileName, "error", err)
	} else {
		err = json.NewEncoder(fh).Encode(m)
		if closeErr := fh.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			Log("msg", "save token", "file", fh.Name(), "error", err)
		}
	}
	return tok, err
}

// NewAuthenticator returns the components for authenticating:
//   1. redirect user to authCodeURL,
//   2. the auth provider will call on conf.RedirectURL, handle it with callbackHandler,
//   3. retrieve the token (or error) on tokenCh.
func NewAuthenticator(conf *oauth2.Config) (
	authCodeURL string, callbackHandler http.Handler, tokenCh chan MaybeToken, err error,
) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, nil, err
	}
	state := base64.URLEncoding.EncodeToString(b[:])
	c := make(chan maybeCode, 1)
	// Redirect user to Google's consent page to ask for permission
	// for the scopes specified above.
	authCodeURL = conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	if conf.RedirectURL == "" {
		return authCodeURL, nil, nil, nil
	}
	tokenCh = make(chan MaybeToken)
	callbackHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRedirect(c, state).ServeHTTP(w, r)
		ce := <-c
		if ce.Code == "" {
			tokenCh <- MaybeToken{Err: err}
			return
		}
		// Handle the exchange code to initiate a transport.
		tok, err := conf.Exchange(r.Context(), ce.Code)
		if err != nil {
			err = fmt.Errorf("exchange code=%s: %w", ce.Code, err)
		}
		tokenCh <- MaybeToken{Token: tok, Err: err}
	})
	return authCodeURL, callbackHandler, tokenCh, nil
}

// Authenticate returns an *oauth.Token for the given Config.
func Authenticate(conf *oauth2.Config, tlsFiles ...string) (*oauth2.Token, error) {
	authCodeURL, callbackHandler, tokenCh, err := NewAuthenticator(conf)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Visit the URL for the auth dialog:\n\n\t%v\n\n", authCodeURL)
	if err := browser.OpenURL(authCodeURL); err != nil {
		Log("msg", "OpenURL", "url", authCodeURL, "error", err)
	}
	if conf.RedirectURL != "" {
		go func() {
			addr := conf.RedirectURL
			if i := strings.Index(addr, "://"); i >= 0 {
				addr = addr[i+3:]
			}
			if len(tlsFiles) == 2 && tlsFiles[0] != "" && tlsFiles[1] != "" {
				http.ListenAndServeTLS(addr, tlsFiles[0], tlsFiles[1], callbackHandler)
			} else {
				http.ListenAndServe(addr, callbackHandler)
			}
		}()
	}

	go func() {
		var code string
		start := time.Now()
		_, err := fmt.Scan(&code)
		if err != nil && time.Since(start) < time.Second {
			Log("msg", "read stdin", "error", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		tok, err := conf.Exchange(ctx, code)
		tokenCh <- MaybeToken{Token: tok, Err: err}
	}()

	mt := <-tokenCh
	return mt.Token, mt.Err
}

type MaybeToken struct {
	Token *oauth2.Token
	Err   error
}

type maybeCode struct {
	Code string
	Err  error
}

func handleRedirect(c chan<- maybeCode, state string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		if gotState := vals.Get("state"); gotState != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := vals.Get("code")
		if code == "" {
			log.Printf("got %s (%q)", r.URL, vals)
			http.Error(w, "empty code", http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, `Please copy the following code into the prompt of the waiting program:

%s`, code)
		c <- maybeCode{Code: code}
	})
}
