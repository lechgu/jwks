package keys

// Key ...
type Key struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	Use     string `json:"use"`
	ID      string `json:"kid"`
	X       string `json:"x"`
	Y       string `json:"y"`
}
