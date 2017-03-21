package encconfig

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestAESCBC normal key initialization
func TestAESCBCInitNormal(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestAESCBC normal key initialization with 128-bit key
func TestAESCBCInit128Key(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestAESCBC normal key initialization with 192-bit key
func TestAESCBCInit192Key(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!12341234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestAESCBC normal key initialization with 256-bit key
func TestAESCBCInit256Key(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!1234567812341234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestAESCBC non-printable key initialization
func TestAESCBCInitNonprintableKey(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!\x11\x22\x01\x035678"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

}

// TestAESCBC key containing null byte initialization
func TestAESCBCInitNullByteKey(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte("this is a key !!\x00\x00\x01\x005678"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}
}

// TestAESCBC multiple random key initialization
func TestAESCBCInitRandomKeyMultiple(t *testing.T) {
	rand_len := 32
	rand_num := 10

	key_bytes := make([]byte, rand_len, rand_len)
	for i := 0; i < rand_num; i++ {
		_, err := rand.Read(key_bytes)
		if err != nil {
			t.Fatalf("Failed to random")
		}

		_, err = NewAESCBCEncConfig(key_bytes)
		if err != nil {
			t.Fatalf("Error initializing key")
		}
	}

}

// TestAESCBC handling of Nil key
func TestAESCBCInitNilKey(t *testing.T) {
	_, err := NewAESCBCEncConfig(nil)
	if err == nil {
		t.Fatalf("Initialized a nil key")
	}

}

// TestAESCBC handling of 0-length key
func TestAESCBCInitZeroKey(t *testing.T) {
	_, err := NewAESCBCEncConfig([]byte{})
	if err == nil {
		t.Fatalf("Initialized a 0-length key")
	}

}

// TestAESCBC handling of invalid length keys
func TestAESCBCInitInvalidKeys(t *testing.T) {
	var err error
	_, err = NewAESCBCEncConfig([]byte("1234"))
	if err == nil {
		t.Fatalf("Initialized a Invalid-length key")
	}

	_, err = NewAESCBCEncConfig([]byte("12341234123412345"))
	if err == nil {
		t.Fatalf("Initialized a Invalid-length key")
	}

	_, err = NewAESCBCEncConfig([]byte("112341234123412342341234123412346"))
	if err == nil {
		t.Fatalf("Initialized a Invalid-length key")
	}
}

/*** Start Encryption Tests ***/

// TestAESCBC checks if encrypting/decrypting change plaintext
func TestAESCBCEncPlainMutate(t *testing.T) {
	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

// TestAESCBC encrypting blocks that are < blockSize
func TestAESCBCEncryptLessThanOneBlock(t *testing.T) {
	p := []byte("small val")
	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

// TestAESCBC encrypting blocks that are > blockSize
func TestAESCBCEncryptBig(t *testing.T) {
	p := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")
	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

// TestAESCBC encrypting null
func TestAESCBCEncryptNull(t *testing.T) {
	var p []byte
	p = nil

	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

// TestAESCBC encrypting empty string
func TestAESCBCEncryptEmpty(t *testing.T) {
	p := []byte("")

	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

// TestAESCBC encrypting blocks that are % blockSize = 0
func TestAESCBCEncryptBlock(t *testing.T) {
	p := []byte("jfowaie3920ejqoi")
	e, err := NewAESCBCEncConfig([]byte("this is a key!!!"))
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

	p = []byte("jfowaie3920ejqoijfowaie3920ejqoi")

	c, err = e.Encrypt(p)
	if err != nil {
		t.Fatalf("Error encrypting plaintext")
	}

	pres, err = e.Decrypt(c)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext")
	}

	result = bytes.Compare(pres, p)

	if result != 0 {
		t.Fatalf("Plaintext doesn't match")
	}

}

// TESTAESCBC Encryption with key byte change after initialization
func TestAESCBCEncryptionKeyPersistance(t *testing.T) {
	p := []byte("this is some plain text")
	key := []byte("this is a key!!!")
	e, err := NewAESCBCEncConfig(key)
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

// TestAESCBC 2 different keys cannot decrypt each other
func TestAESCBCKeyDifference(t *testing.T) {
	p := []byte("This is some plaintext")

	e1, err := NewAESCBCEncConfig([]byte("this is key 1234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	e2, err := NewAESCBCEncConfig([]byte("this is key abcd"))
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

// TestAESCBC 2 same keys can decrypt each other
func TestAESCBCKeySame(t *testing.T) {
	p := []byte("This is some plaintext")

	e1, err := NewAESCBCEncConfig([]byte("this is key 1234"))
	if err != nil {
		t.Fatalf("Error initializing key")
	}

	e2, err := NewAESCBCEncConfig([]byte("this is key 1234"))
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

// TestAESCBC for concurrent encryption/decryptions
func TestAESCBCConcurrency(t *testing.T) {
	key := []byte("this is a key!!!")
	e, err := NewAESCBCEncConfig(key)
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
		}

		for i := 0; i < iterations; i++ {
			c, err := e.Encrypt(p)
			if err != nil {
				t.Error("Error encrypting plaintext")
			}

			pres, err := e.Decrypt(c)
			if err != nil {
				t.Error("Error decrypting ciphertext")
			}

			result := bytes.Compare(pres, p)

			if result != 0 {
				t.Error("Plaintext doesn't match")
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
