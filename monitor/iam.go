package monitor

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

type TokenContext struct {
	roles []string
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
	} else {
		return nil
	}
}

func (iam *iam) mapToContext(token *jwt.Token) (TokenContext, error) {
	claims := token.Claims.(jwt.MapClaims)
	//TODO: return usable errors
	err := fmt.Errorf("Not able to optain roles from token")
	if realmAccess, ok := claims["realm_access"]; ok {
		if realmMap, ok := realmAccess.(map[string][]string); ok {
			if roles, ok := realmMap["roles"]; ok {

				return TokenContext{
					roles: roles,
				}, nil

			} else {
				err = fmt.Errorf("unable to get roles from realmMap %+v", realmMap)
			}
		} else {
			err = fmt.Errorf("realm_access was not in the expected format %+v", realmAccess)
		}
	} else {
		err = fmt.Errorf("unable to optain realm_access from token")

	}
	return TokenContext{}, err

}

func (iam *iam) GetNewKey(keyID string) (interface{}, error) {
	set, err := jwk.FetchHTTP(iam.conf.JWKSURL)
	if err != nil {
		return nil, err
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, fmt.Errorf("Could not optain new key")

}
