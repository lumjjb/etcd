package encconfig

import (
	"errors"
)

type otpEncConfig struct {
	key []byte
}

var (
	ErrKeyInvalidLength = errors.New("Invalid Key Length")
)

func NewOTPEncConfig(key []byte) (EncConfig, error) {
	if len(key) <= 0 {
		return nil, ErrKeyInvalidLength
	}

	encConf := otpEncConfig{
		key: make([]byte, len(key)),
	}

	// Create local key for closure
	copy(encConf.key, key)

	return &encConf, nil
}

func (e *otpEncConfig) Encrypt(m []byte) ([]byte, error) {
	keyLen := len(e.key)
	out := make([]byte, len(m))
	for i, _ := range m {
		out[i] = m[i] ^ e.key[i%keyLen]
	}
	return []byte(out), nil
}

func (e *otpEncConfig) Decrypt(m []byte) ([]byte, error) {
	return e.Encrypt(m)
}
