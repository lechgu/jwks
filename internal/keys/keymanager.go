package keys

import (
	"crypto/ecdsa"
	"time"
)

// KeyManager ...
type KeyManager struct {
	Cache map[string]*ecdsa.PrivateKey
	Jwks  *KeySet
}

// NewKeyManager ...
func NewKeyManager() (*KeyManager, error) {
	km := KeyManager{
		Cache: make(map[string]*ecdsa.PrivateKey),
		Jwks:  NewKeySet(),
	}
	for i := 0; i < 3; i++ {
		kid, key, error := km.Jwks.GenerateNewKey()
		if error != nil {
			return nil, error
		}
		km.Cache[kid] = key
		time.Sleep(time.Second)
	}

	return &km, nil
}
