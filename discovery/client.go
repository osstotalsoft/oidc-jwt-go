package discovery

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Options struct {
	Authority string
}

type Client struct {
	Options Options
}

type Discoverer interface {
	GetOpenidConfiguration() (OpenidConfiguration, error)
}

func NewClient(options Options) *Client {
	return &Client{Options: options}
}

func (client *Client) GetOpenidConfiguration() (OpenidConfiguration, error) {
	var cfg = OpenidConfiguration{}

	resp, err := http.Get(singleJoiningSlash(client.Options.Authority, ".well-known/openid-configuration"))
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&cfg)
	if err != nil {
		return cfg, err
	}

	resp2, err := http.Get(cfg.JwksUri)
	if err != nil {
		return cfg, err
	}
	defer resp2.Body.Close()

	var jwks = JsonWebKeySet{}
	err = json.NewDecoder(resp2.Body).Decode(&jwks)
	if err != nil {
		return cfg, err
	}

	cfg.JsonWebKeySet = jwks.Keys

	return cfg, err
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash && b != "":
		return a + "/" + b
	}
	return a + b
}
