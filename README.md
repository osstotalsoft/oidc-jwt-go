# oidc-jwt-go
OpenID Connect package to secure your API using JWT Bearer tokens.
It uses [dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) for jwt decoding and signature verification
 
## Installation
`go get "github.com/osstotalsoft/oidc-jwt-go" `

## Usage
````go
import (
	"log"
	"net/http"

	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/osstotalsoft/oidc-jwt-go"
)

func middleware() func(next http.Handler) http.Handler {
	authority := "https://accounts.google.com" //or other OIDC provider
	audience := "YOUR_API_NAME"

	secretProvider := oidc.NewOidcSecretProvider(discovery.NewClient(discovery.Options{authority}))
	validator := oidc.NewJWTValidator(jwtRequest.OAuth2Extractor, secretProvider, audience, authority)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			token, err := validator(request)
			if err != nil {
				log.Error("AuthorizationFilter: Token is not valid", err)
				UnauthorizedWithHeader(writer, err.Error())
				return
			}
			next.ServeHttp(writer, request)
		})
	}
}

//UnauthorizedWithHeader adds to the response a WWW-Authenticate header and returns a StatusUnauthorized error
func UnauthorizedWithHeader(writer http.ResponseWriter, err string) {
	writer.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\""+err+"\"")
	http.Error(writer, "", http.StatusUnauthorized)
}
````

## Caching 
The Secret Provider uses a simple sync.Map, with no expiration, to cache the rsa.PublicKey by a Key ID string  

## TODO
 - Token Introspection [rfc7662](https://tools.ietf.org/html/rfc7662)
 - UserInfo [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
 
## Similar projects
 - https://github.com/auth0-community/go-auth0
 - https://github.com/auth0/go-jwt-middleware
 - https://github.com/appleboy/gin-jwt
