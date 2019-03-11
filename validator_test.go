package oidc

import (
	"github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/dgrijalva/jwt-go/test"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var Authority = "http://kube-worker1:30692"
var Audience = "LSNG.Api"

var claims = jwt.MapClaims{
	"iss": "http://kube-worker1:30692",
	"aud": []string{
		"http://kube-worker1:30692/resources",
		"LSNG.Api",
		"Notifier.Api",
	},
	"client_id":        "CharismaFinancialServices",
	"sub":              "c8124881-ad67-443e-9473-08d5777d1ba8",
	"idp":              "local",
	"partner_id":       "-100",
	"charisma_user_id": "1",
	"scope": []string{
		"openid",
		"profile",
		"roles",
		"LSNG.Api.read_only",
		"charisma_data",
		"Notifier.Api.write",
	},
	"amr": []string{
		"pwd",
	},
}

func TestValidator(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("./test/sample_key")
	publicKey := test.LoadRSAPublicKeyFromDisk("./test/sample_key.pub")

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	validator := NewJWTValidator(jwtRequest.OAuth2Extractor, NewKeyProvider(publicKey), Audience, Authority)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := validator(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, err.Error())
		} else {
			_, _ = io.WriteString(w, "OK")
		}
	})
	req := httptest.NewRequest("GET", "/whatever", nil)
	req.Header.Add("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	result := w.Result()

	if result.StatusCode != http.StatusOK {
		t.Error("request failed status: ", result.StatusCode)
	}
}

func BenchmarkTestValidator(b *testing.B) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("./test/sample_key")
	publicKey := test.LoadRSAPublicKeyFromDisk("./test/sample_key.pub")
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	validator := NewJWTValidator(jwtRequest.OAuth2Extractor, NewKeyProvider(publicKey), Audience, Authority)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := validator(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, err.Error())
		} else {
			_, _ = io.WriteString(w, "OK")
		}
	})
	req := httptest.NewRequest("GET", "/whatever", nil)
	req.Header.Add("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
		w.Result()
	}
}
