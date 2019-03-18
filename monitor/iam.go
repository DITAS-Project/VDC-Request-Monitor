package monitor

import (
	"github.com/lestrrat/go-jwx/jwk"
)

type iam struct {
	keyCache map[string][]jwk.Key
}

func NewIAM(conf Configuration) *iam {
	return &iam{
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

func (iam *iam) StoreKeyID(keyID string, key []jwk.Key) {
	iam.keyCache[keyID] = key
}
