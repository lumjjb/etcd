package encconfig

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestOTP normal key initialization
func TestOTPInitNormal(t *testing.T) {
	_, err := NewOTPEncConfig([]byte("this is a key"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestOTP normal key initialization with length 1 key
func TestOTPInitOneKey(t *testing.T) {
	_, err := NewOTPEncConfig([]byte("1"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestOTP normal key initialization with long length key
func TestOTPInitBigKey(t *testing.T) {
	_, err := NewOTPEncConfig([]byte("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestOTP non-printable key initialization
func TestOTPInitNonprintableKey(t *testing.T) {
	_, err := NewOTPEncConfig([]byte{0xbd, 0xb2, 0x3d, 0xbc, 0x20, 0xe2, 0x8c, 0x98})
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestOTP key containing null byte initialization
func TestOTPInitNullByteKey(t *testing.T) {
	_, err := NewOTPEncConfig([]byte{'1', 0x00, '1'})
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestOTP multiple random key initialization
func TestOTPInitRandomKeyMultiple(t *testing.T) {
	rand_len := 32
	rand_num := 10

	key_bytes := make([]byte, rand_len, rand_len)
	for i := 0; i < rand_num; i++ {
		_, err := rand.Read(key_bytes)
		if err != nil {
			t.Fatalf("Failed to random")
		}

		_, err = NewOTPEncConfig(key_bytes)
		if err != nil {
			t.Fatalf("Error initializing key")
		}
	}
}

// TestOTP handling of Nil key
func TestOTPInitNilKey(t *testing.T) {
	_, err := NewOTPEncConfig(nil)
	if err == nil {
		t.Fatalf("Initialized a nil key")
	}

}

// TestOTP handling of 0-length key
func TestOTPInitZeroKey(t *testing.T) {
	_, err := NewOTPEncConfig([]byte{})
	if err == nil {
		t.Fatalf("Initialized a 0-length key")
	}
}

/*** ENCRYPTION TESTS ***/

// TestOTP normal key encryption and decryption
func TestOTPEncNormal(t *testing.T) {
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	for _, p := range plaintexts {
		c, err := e.Encrypt(p)
		if err != nil {
			t.Fatalf("Error encrypting plaintext")
		}

		pres, err := e.Decrypt(c)
		if err != nil {
			t.Fatalf("Error decrypting ciphertext")
		}

		result := bytes.Compare(pres, p)

		if result != 0 {
			t.Fatalf("Plaintext doesn't match")
		}
	}
}

// TestOTP checks if encrypting/decrypting change plaintext
func TestOTPEncPlainMutate(t *testing.T) {
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	for _, p := range plaintexts {
		pcopy := make([]byte, len(p))
		copy(pcopy, p)
		c, err := e.Encrypt(p)
		if err != nil {
			t.Fatalf("Error encrypting plaintext")
		}

		if bytes.Compare(pcopy, p) != 0 {
			t.Fatalf("Plaintext mutated")
		}

		_, err = e.Decrypt(c)
		if err != nil {
			t.Fatalf("Error decrypting ciphertext")
		}

		if bytes.Compare(pcopy, p) != 0 {
			t.Fatalf("Plaintext mutated")
		}
	}
}

// TestOTP multiple random key encryption and decryption
func TestOTPEncRandomKeyMultiple(t *testing.T) {
	for _, p := range plaintexts {

		rand_len := 32
		rand_num := 10

		var e EncConfig

		key_bytes := make([]byte, rand_len, rand_len)
		for i := 0; i < rand_num; i++ {
			_, err := rand.Read(key_bytes)
			if err != nil {
				t.Fatalf("Failed to random")
			}

			e, err = NewOTPEncConfig(key_bytes)
			if err != nil {
				t.Fatalf("Error initializing key")
			}
		}

		pcopy := make([]byte, len(p))
		copy(pcopy, p)
		c, err := e.Encrypt(p)
		if err != nil {
			t.Fatalf("Error encrypting plaintext")
		}

		pres, err := e.Decrypt(c)
		if err != nil {
			t.Fatalf("Error decrypting ciphertext")
		}

		result := bytes.Compare(pres, p)

		if result != 0 {
			t.Fatalf("Plaintext doesn't match")
		}
	}
}

// TestOTP 2 different keys cannot decrypt each other
func TestOTPKeyDifference(t *testing.T) {
	p := []byte("This is some plaintext")

	e1, err := NewOTPEncConfig([]byte("this is key 1234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	e2, err := NewOTPEncConfig([]byte("this is key abcd"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c1, err := e1.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}
	c2, err := e2.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	p1, err := e1.Decrypt(c2)
	if err == nil && bytes.Compare(p, p1) == 0 {
		t.Fatalf("Key 1 decrypted key 2 ciphertext")
	}

	p2, err := e2.Decrypt(c1)
	if err == nil && bytes.Compare(p, p2) == 0 {
		t.Fatalf("Key 2 decrypted key 1 ciphertext")
	}

}

// TestOTP 2 same keys can decrypt each other
func TestOTPKeySame(t *testing.T) {
	p := []byte("This is some plaintext")

	e1, err := NewOTPEncConfig([]byte("this is key 1234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	e2, err := NewOTPEncConfig([]byte("this is key 1234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c1, err := e1.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}
	c2, err := e2.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	p1, err := e1.Decrypt(c2)
	if err != nil || bytes.Compare(p, p1) != 0 {
		t.Fatalf("Couldn't decrypt with initialization of same key")
	}

	p2, err := e2.Decrypt(c1)
	if err != nil || bytes.Compare(p, p2) != 0 {
		t.Fatalf("Couldn't decrypt with initialization of same key")
	}
}

// TestOTP encrypting null
func TestOTPEncryptNull(t *testing.T) {
	var p []byte
	p = nil

	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	// If error on encryption - ok
	c, err := e.Encrypt(p)
	if err != nil {
		return
	}

	// Else should decrypt to nil equivalent
	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	if len(pres) > 0 {
		t.Fatalf("Non null decryption")
	}
}

// TestOTP encrypting empty string
func TestOTPEncryptEmpty(t *testing.T) {
	p := []byte("")

	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	// If error on encryption - ok
	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	// Else should decrypt to nil equivalent
	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	if bytes.Compare(pres, []byte{}) != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TESTOTP Encrypting small len(plaintext) < len(key)
func TestOTPEncryptSmall(t *testing.T) {
	p := []byte("small val")
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result := bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TESTOTP Encrypting big len(plaintext) > len(key)
func TestOTPEncryptBig(t *testing.T) {
	p := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result := bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TESTOTP Encrypting len(plaintext) = len(key)
func TestOTPEncryptMedium(t *testing.T) {
	p := []byte("jfowaie3920ejqoi")
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result := bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TESTOTP Encrypting plaintext = key
func TestOTPEncryptIdentical(t *testing.T) {
	p := []byte("this is a key!!!")
	e, err := NewOTPEncConfig([]byte("this is a key!!!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result := bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TESTOTP Encryption with key byte change after initialization
func TestOTPEncryptionKeyPersistance(t *testing.T) {
	p := []byte("this is some plain text")
	key := []byte("this is a key!!!")
	e, err := NewOTPEncConfig(key)
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	c, err := e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	key[0] = '5'
	key[1] = '5'
	key[2] = '5'
	key[3] = '5'

	pres, err := e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result := bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}
}

// TestOTP for concurrent encryption/decryptions
func TestOTPConcurrency(t *testing.T) {

	key := []byte("this is a key!!!")
	e, err := NewOTPEncConfig(key)
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	done := make(chan bool)

	iterations := 1000
	enc_test := func() {
		p := make([]byte, 128)
		_, err := rand.Read(p)
		if err != nil {
			t.Error("Error creating random plaintext")
			done <- false
			return
		}

		for i := 0; i < iterations; i++ {
			c, err := e.Encrypt(p)
			if err != nil {
				t.Error("Error encrypting plaintext")
				done <- false
				return
			}

			pres, err := e.Decrypt(c)
			if err != nil {
				t.Error("Error decrypting ciphertext")
				done <- false
				return
			}

			result := bytes.Compare(pres, p)

			if result != 0 {
				t.Error("Plaintext doesn't match")
				done <- false
				return
			}
		}

		done <- true
	}

	routines := 100
	for i := 0; i < routines; i++ {
		go enc_test()
	}

	for i := 0; i < routines; i++ {
		if b := <-done; !b {
			t.Fatal("Concurrency Problem")
		}
	}
}
