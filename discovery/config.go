package discovery

type OpenidConfiguration struct {
	Issuer                             string       `json:"issuer"`
	JwksUri                            string       `json:"jwks_uri"`
	AuthorizationEndpoint              string       `json:"authorization_endpoint"`
	TokenEndpoint                      string       `json:"token_endpoint"`
	UserinfoEndpoint                   string       `json:"userinfo_endpoint"`
	EndSessionEndpoint                 string       `json:"end_session_endpoint"`
	CheckSessionIframe                 string       `json:"check_session_iframe"`
	RevocationEndpoint                 string       `json:"revocation_endpoint"`
	IntrospectionEndpoint              string       `json:"introspection_endpoint"`
	FrontchannelLogoutSupported        string       `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported string       `json:"frontchannel_logout_session_supported"`
	BackchannelLogoutSupported         string       `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported  string       `json:"backchannel_logout_session_supported"`
	ScopesSupported                    []string     `json:"scopes_supported"`
	ClaimsSupported                    []string     `json:"claims_supported"`
	GrantTypesSupported                []string     `json:"grant_types_supported"`
	ResponseTypesSupported             []string     `json:"response_types_supported"`
	ResponseModesSupported             []string     `json:"response_modes_supported"`
	TokenEndpointAuthMethodsSupported  []string     `json:"token_endpoint_auth_methods_supported"`
	SubjectTypesSupported              []string     `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported   []string     `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported      []string     `json:"code_challenge_methods_supported"`
	JsonWebKeySet                      []JsonWebKey `json:"-"`
}

type JsonWebKeySet struct {
	Keys []JsonWebKey `json:"keys"`
}

type JsonWebKey struct {
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}
