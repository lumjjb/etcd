package encconfig

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// AES Key Length Constants
	AES_128_KEY_LEN = 128 / 8
	AES_192_KEY_LEN = 192 / 8
	AES_256_KEY_LEN = 256 / 8
)

var (
	// AES Errors
	ErrInvalidKeyLength = errors.New("Invalid Key Length")

	// PKCS Errors
	ErrPKCS7PaddingLengthInvalid     = errors.New("PKCS#7 Padding Invalid")
	ErrPKCS7PaddingInvalid           = errors.New("PKCS#7 Padding Invalid")
	ErrPKCS7PaddingBytesInsufficient = errors.New("PKCS#7 not enough pad bytes")
)

// AES CBC EncConfig to hold AES metadata
type aesCBCEncConfig struct {
	key       []byte
	blockSize int
}

// Creates an EncConfig which performs AES Encrypt/Decrypt with given key in
// CBC mode
func NewAESCBCEncConfig(key []byte) (EncConfig, error) {
	if len(key) != AES_128_KEY_LEN &&
		len(key) != AES_192_KEY_LEN &&
		len(key) != AES_256_KEY_LEN {
		return nil, ErrInvalidKeyLength
	}

	encConf := aesCBCEncConfig{
		key:       make([]byte, len(key), len(key)),
		blockSize: aes.BlockSize,
	}

	copy(encConf.key, key)

	return &encConf, nil
}

func pkcs7pad(m []byte, bsize uint16) []byte {
	dataSize := len(m)
	blockSize := int(bsize)

	numPad := blockSize - (dataSize % blockSize)
	padding := bytes.Repeat([]byte{byte(numPad)}, numPad)

	return append(m, padding...)
}

func pkcs7unpad(m []byte, bsize uint16) ([]byte, error) {

	size := len(m)
	blockSize := int(bsize)

	// Can't have 0 since it would pad to at least 1 block size
	if size == 0 {
		return nil, ErrPKCS7PaddingLengthInvalid
	}
	numPad := int(m[size-1])

	// Padding number can't be 0
	if numPad == 0 {
		return nil, ErrPKCS7PaddingInvalid
	}

	// Not enough padding exists or the padding number is more than blockSize
	if numPad > size || numPad > blockSize {
		return nil, ErrPKCS7PaddingInvalid
	}

	// Validate the padding (precautionary measure)
	padding := m[size-numPad:]
	for _, k := range padding {
		if k != byte(numPad) {
			return nil, ErrPKCS7PaddingInvalid
		}
	}

	msg := m[:size-numPad]

	return msg, nil
}

var (
	ErrAESCipherBlockSizeNotMultiple = errors.New("AES ciphertext not multiple of block size")
	ErrAESCipherTooShort             = errors.New("AES ciphertext doesn't meet minimum length requirements")
)

// Enc/Dec Code adapted from crypto lib docs
// https://golang.org/src/crypto/cipher/example_test.go
func (e *aesCBCEncConfig) Encrypt(plaintext []byte) ([]byte, error) {

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. We will use PKCS#7 Padding.
	plaintext = pkcs7pad(plaintext, uint16(e.blockSize))

	block, encErr := aes.NewCipher(e.key)
	if encErr != nil {
		return nil, encErr
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, encErr := io.ReadFull(rand.Reader, iv); encErr != nil {
		return nil, encErr
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func (e *aesCBCEncConfig) Decrypt(ciphertext []byte) ([]byte, error) {
	block, decErr := aes.NewCipher(e.key)
	if decErr != nil {
		return nil, decErr
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrAESCipherTooShort
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrAESCipherBlockSizeNotMultiple
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext), len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, decErr = pkcs7unpad(plaintext, uint16(e.blockSize))
	if decErr != nil {
		return nil, nil
	}

	return plaintext, nil
}
