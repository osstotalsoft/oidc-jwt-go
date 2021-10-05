package oidc

import (
	"crypto/rsa"
	"errors"

	"sync"

	"github.com/golang-jwt/jwt"
	"github.com/osstotalsoft/oidc-jwt-go/discovery"
)

type SecretProvider interface {
	GetSecret(tokenKeyId string) (key *rsa.PublicKey, err error)
}

type SecretProviderFunc func(tokenKeyId string) (*rsa.PublicKey, error)

func (f SecretProviderFunc) GetSecret(tokenKeyId string) (*rsa.PublicKey, error) {
	return f(tokenKeyId)
}

// NewKeyProvider provide a simple passphrase key provider.
func NewKeyProvider(publicKey *rsa.PublicKey) SecretProvider {
	return SecretProviderFunc(func(tokenKeyId string) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
}

type oidcSecretProvider struct {
	configurationDiscoverer discovery.Discoverer
	cache                   sync.Map
}

func NewOidcSecretProvider(configurationDiscoverer discovery.Discoverer) *oidcSecretProvider {
	return &oidcSecretProvider{configurationDiscoverer: configurationDiscoverer}
}

func (p *oidcSecretProvider) GetSecret(tokenKeyId string) (*rsa.PublicKey, error) {

	if tokenKeyId == "" {
		return nil, errors.New("KeyId header not found in token")
	}

	key, found := p.cache.Load(tokenKeyId)
	if found {
		return key.(*rsa.PublicKey), nil
	}

	publicKey, err := p.interalGetSecret(tokenKeyId)
	if err == nil {
		p.cache.Store(tokenKeyId, publicKey)
	}
	return publicKey, err
}

func (p *oidcSecretProvider) interalGetSecret(tokenKeyId string) (*rsa.PublicKey, error) {

	config, err := p.configurationDiscoverer.GetOpenidConfiguration()
	if err != nil {
		return nil, err
	}

	var cert = ""
	for _, jwk := range config.JsonWebKeySet {
		if tokenKeyId == jwk.Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwk.X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
}
