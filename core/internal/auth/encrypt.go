package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptionKeyBytes is the key length required for AES-256-GCM.
const EncryptionKeyBytes = 32

// Encrypt seals plaintext with AES-256-GCM under key, returning the ciphertext and the
// fresh random nonce it was sealed with.
//
// A TOTP secret, unlike a password, has to be recoverable in order to verify a code, so
// hashing is not available and encryption is what stops a leaked database dump from
// being a complete set of working second factors. The nonce is returned separately
// rather than prepended so the store can keep it in its own column, where it is visibly
// a nonce rather than an opaque prefix someone later has to rediscover.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// Decrypt opens a ciphertext produced by Encrypt. An error means the key is wrong, the
// nonce does not belong to this ciphertext, or the data has been tampered with — GCM
// authenticates, so there is no path where this returns plausible garbage.
func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", gcm.NonceSize(), len(nonce))
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != EncryptionKeyBytes {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", EncryptionKeyBytes, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
