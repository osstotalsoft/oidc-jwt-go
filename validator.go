package oidc

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt"
	jwtRequest "github.com/golang-jwt/jwt/request"
)

func NewJWTValidator(extractor jwtRequest.Extractor, provider SecretProvider, audience string, authority string) func(request *http.Request) (*jwt.Token, error) {
	if extractor == nil {
		extractor = jwtRequest.OAuth2Extractor
	}

	return func(request *http.Request) (*jwt.Token, error) {

		token, err := jwtRequest.ParseFromRequest(request, extractor, func(token *jwt.Token) (i interface{}, e error) {
			if id, ok := token.Header["kid"]; ok {
				return provider.GetSecret(id.(string))
			}
			return provider.GetSecret("")
		})
		if err != nil {
			return nil, err
		}

		checkAud := verifyAudience(audience, token.Claims.(jwt.MapClaims)["aud"])
		if !checkAud {
			return token, errors.New("invalid audience")
		}

		// Verify 'iss' claim
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(authority, true)
		if !checkIss {
			return token, errors.New("invalid issuer")
		}
		return token, err
	}
}

func verifyAudience(audience string, tokenAudience interface{}) bool {
	switch tokenAudience.(type) {
	case string:
		return tokenAudience == audience
	case []interface{}:
		{
			for _, aud := range tokenAudience.([]interface{}) {
				if aud == audience {
					return true
				}
			}
		}
	}

	return false
}
