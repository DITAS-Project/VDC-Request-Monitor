package monitor

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

type DITASClaims struct {
	*jwt.StandardClaims
	Relams map[string][]string `json:"realm_access"`
	User   string              `json:"preferred_username"`
}

type TokenContext struct {
	roles []string
	user  string
}

type iam struct {
	conf     Configuration
	keyCache map[string][]jwk.Key
}

func NewIAM(conf Configuration) *iam {
	return &iam{
		conf:     conf,
		keyCache: make(map[string][]jwk.Key),
	}
}

func (iam *iam) LookupKeyID(keyID string) []jwk.Key {
	if keys, ok := iam.keyCache[keyID]; ok {
		return keys
	}
	return nil

}

func (iam *iam) mapToContext(token *jwt.Token) (TokenContext, error) {
	var err error
	context := TokenContext{}
	if claims, ok := token.Claims.(*DITASClaims); ok {
		context.user = claims.User

		if roles, ok := claims.Relams["roles"]; ok {
			context.roles = roles
		} else {
			err = fmt.Errorf("failed to extract roles from claim")
		}

	} else {
		err = fmt.Errorf("faield to cast claims %+v", token.Claims)
	}

	return context, err
}

func (iam *iam) GetNewKey(keyID string) (interface{}, error) {
	set, err := jwk.FetchHTTP(iam.conf.JWKSURL)
	if err != nil {
		return nil, err
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		iam.keyCache[keyID] = key
		return key[0].Materialize()
	}

	return nil, fmt.Errorf("Could not optain new key")

}
