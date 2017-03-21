package encconfig

// Encryption Configuration internal structure
type EncConfig interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}
