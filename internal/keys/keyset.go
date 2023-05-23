package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// KeySet ...
type KeySet struct {
	Keys []Key `json:"keys"`
}

// NewKeySet ...
func NewKeySet() *KeySet {
	return &KeySet{
		Keys: []Key{},
	}
}

// GenerateNewKey ...
func (ks *KeySet) GenerateNewKey() (string, *ecdsa.PrivateKey, error) {
	pk, error := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if error != nil {
		return "", nil, error
	}
	now := time.Now().UTC().Format(time.RFC3339)
	kid := fmt.Sprintf("stash-sig-%s", now)

	key := Key{
		KeyType: "EC",
		Curve:   "P-256",
		Use:     "sig",
		ID:      kid,
		X:       base64.RawURLEncoding.EncodeToString(pk.PublicKey.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(pk.PublicKey.Y.Bytes()),
	}
	ks.Keys = append(ks.Keys, key)
	return kid, pk, nil
}
