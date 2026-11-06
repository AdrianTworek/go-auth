package auth

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, EncryptionKeyBytes)
}

func Test_Encrypt_RoundTrip(t *testing.T) {
	key := testKey(0x2a)
	secret, err := NewTOTPSecret()
	require.NoError(t, err)

	ciphertext, nonce, err := Encrypt(key, secret)
	require.NoError(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted, err := Decrypt(key, ciphertext, nonce)
	require.NoError(t, err)
	assert.Equal(t, secret, decrypted)
}

// Test_Encrypt_NonceIsFresh is the property that makes GCM safe to use here at all:
// reusing a nonce under the same key is catastrophic for GCM, so two encryptions of the
// same plaintext must not produce the same ciphertext.
func Test_Encrypt_NonceIsFresh(t *testing.T) {
	key := testKey(0x2a)
	plaintext := []byte("the same secret twice")

	firstCipher, firstNonce, err := Encrypt(key, plaintext)
	require.NoError(t, err)
	secondCipher, secondNonce, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, firstNonce, secondNonce)
	assert.NotEqual(t, firstCipher, secondCipher)
}

// Test_Decrypt_RejectsTampering is why this is AEAD rather than a bare cipher: a
// modified ciphertext fails loudly instead of decrypting to a different secret, which
// would otherwise be an attacker-chosen second factor.
func Test_Decrypt_RejectsTampering(t *testing.T) {
	key := testKey(0x2a)
	plaintext := []byte("authenticator secret")

	ciphertext, nonce, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		tampered := bytes.Clone(ciphertext)
		tampered[0] ^= 0x01

		_, err := Decrypt(key, tampered, nonce)
		assert.Error(t, err)
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		tampered := bytes.Clone(nonce)
		tampered[0] ^= 0x01

		_, err := Decrypt(key, ciphertext, tampered)
		assert.Error(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		_, err := Decrypt(testKey(0x2b), ciphertext, nonce)
		assert.Error(t, err)
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		_, err := Decrypt(key, ciphertext[:len(ciphertext)-1], nonce)
		assert.Error(t, err)
	})
}

// Test_Encrypt_RejectsBadKeyLength guards the error path that AuthConfig validation
// relies on. A key of the wrong length must be an error here, not a panic, so that the
// construction-time check has something to report.
func Test_Encrypt_RejectsBadKeyLength(t *testing.T) {
	for _, length := range []int{0, 1, 16, 31, 33, 64} {
		key := bytes.Repeat([]byte{0x2a}, length)

		_, _, err := Encrypt(key, []byte("secret"))
		require.Error(t, err, "key length %d", length)
		assert.Contains(t, err.Error(), "32 bytes")

		_, err = Decrypt(key, []byte("ciphertext"), []byte("nonce"))
		assert.Error(t, err, "key length %d", length)
	}
}

func Test_Decrypt_RejectsBadNonceLength(t *testing.T) {
	key := testKey(0x2a)
	ciphertext, nonce, err := Encrypt(key, []byte("secret"))
	require.NoError(t, err)

	_, err = Decrypt(key, ciphertext, nonce[:len(nonce)-1])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce must be")
}
