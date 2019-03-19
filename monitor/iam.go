package monitor

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

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
	} else {
		return nil
	}
}

func (iam *iam) mapToContext(token *jwt.Token) (TokenContext, error) {
	claims := token.Claims.(jwt.MapClaims)

	var err error
	var roles []string
	var user string

	if realmAccess, ok := claims["realm_access"]; ok {
		if realmMap, ok := realmAccess.(map[string][]string); ok {
			if tmp, ok := realmMap["roles"]; !ok {
				err = fmt.Errorf("unable to get roles from realmMap %+v", realmMap)
			} else {
				roles = tmp
			}
		} else {
			err = fmt.Errorf("realm_access was not in the expected format %+v", realmAccess)
		}

	} else {
		err = fmt.Errorf("realm missing in token")
	}

	if preferred_username, ok := claims["preferred_username"]; ok {
		if tmp, ok := preferred_username.(string); !ok {
			err = fmt.Errorf("preferred_username was not in the expected format %+v", preferred_username)
		} else {
			user = tmp
		}
	} else {
		err = fmt.Errorf("preferred_username missing in token")
	}

	return TokenContext{
		roles: roles,
		user:  user,
	}, err

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
