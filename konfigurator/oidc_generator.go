package konfigurator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/skratchdot/open-golang/open"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-rootcerts"
)

// OidcGenerator deals with OIDC information such as the redirect endpoint and all the Oauth2 config.
type OidcGenerator struct {
	ctx                   context.Context
	config                oauth2.Config
	localURL              string
	localRedirectEndpoint string
	Run                   func(string) error
	Stream                io.Writer
}

func httpClient() (*http.Client, error) {
	tlsConfig := &tls.Config{}
	err := rootcerts.ConfigureTLS(tlsConfig, &rootcerts.Config{
	//CAFile: os.Getenv("MYAPP_CAFILE"),
	//CAPath: os.Getenv("MYAPP_CAPATH"),
	})
	if err != nil {
		return nil, err
	}
	c := cleanhttp.DefaultClient()
	t := cleanhttp.DefaultTransport()
	t.TLSClientConfig = tlsConfig
	c.Transport = t
	return c, nil
}

// NewOidcGenerator uses a default background context and 'localhost' for the redirectUrl and returns a new OidcGenerator struct.
func NewOidcGenerator(hostURL, clientID, localPort, localRedirectEndpoint string) (*OidcGenerator, error) {
	ctx := context.Background()

	client, err := httpClient()

	if err != nil {
		return nil, err
	}

	httpctx := context.WithValue(ctx, oauth2.HTTPClient, client)

	provider, err := oidc.NewProvider(httpctx, hostURL)
	if err != nil {
		return nil, err
	}

	localURL := "localhost:" + localPort
	return &OidcGenerator{
		ctx: ctx,
		config: oauth2.Config{
			ClientID:    clientID,
			RedirectURL: "http://" + localURL + localRedirectEndpoint,
			Endpoint:    provider.Endpoint(),
		},
		localURL:              localURL,
		localRedirectEndpoint: localRedirectEndpoint,
		Run:    open.Run,
		Stream: os.Stderr,
	}, nil
}

// AuthCodeURL calls the underlying oauth2.Config AuthCodeURL.
func (o *OidcGenerator) AuthCodeURL(state, nonceValue string) string {
	redirect := url.Values{}
	redirect.Add("client_id", o.config.ClientID)
	redirect.Add("nonce", nonceValue)
	redirect.Add("redirect_uri", o.config.RedirectURL)
	redirect.Add("response_type", "id_token")
	redirect.Add("scope", "openid")
	redirect.Add("state", state)
	return fmt.Sprintf("%s?%s", o.config.Endpoint.AuthURL, redirect.Encode())
}

// OpenBrowser opens a browser with the given url
func (o *OidcGenerator) OpenBrowser() {
	if err := o.Run("http://" + o.localURL); err != nil {
		fmt.Fprintf(o.Stream, "Go to the following url to authenticate: http://%s/", o.localURL)
	}
}

// GetToken retrieves the Oauth2 token from the request and extracts the "id_token" part of it.
func (o *OidcGenerator) GetToken(code string) (string, error) {
	oauth2Token, err := o.config.Exchange(o.ctx, code)
	if err != nil {
		return "", err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("missing id_token from oauth2 token")
	}

	return rawIDToken, nil
}
