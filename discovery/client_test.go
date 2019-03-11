package discovery

import (
	"testing"
)

func TestClient_GetOpenidConfiguration(t *testing.T) {
	cl := NewClient(Options{Authority: "https://tech0.eu.auth0.com/"})
	r, err := cl.GetOpenidConfiguration()

	if err != nil {
		t.Error(err)
	}

	if r.Issuer != cl.Options.Authority {
		t.Errorf("Issuer does not match : expected %s got %s", r.Issuer, cl.Options.Authority)
	}

	if len(r.JsonWebKeySet) == 0 {
		t.Errorf("no JsonWebKeySetdoes found")
	}

}
