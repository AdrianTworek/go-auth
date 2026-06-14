package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateSecureToken(t *testing.T) {
	_, err := GenerateSecureToken(0)
	assert.Error(t, err)
	_, err = GenerateSecureToken(-1)
	assert.Error(t, err)

	tok, err := GenerateSecureToken(32)
	require.NoError(t, err)
	assert.NotEmpty(t, tok)

	raw, err := base64.URLEncoding.DecodeString(tok)
	require.NoError(t, err)
	assert.Len(t, raw, 32) // decodes to exactly n bytes

	tok2, err := GenerateSecureToken(32)
	require.NoError(t, err)
	assert.NotEqual(t, tok, tok2) // tokens are unique
}

func TestHashToken(t *testing.T) {
	assert.Equal(t, HashToken("abc"), HashToken("abc")) // deterministic
	assert.NotEqual(t, HashToken("abc"), HashToken("abd"))
	assert.Len(t, HashToken("abc"), 64) // hex-encoded SHA-256
}

func TestHashedSetCompare(t *testing.T) {
	var h Hashed
	require.NoError(t, h.Set("s3cr3t!"))
	assert.NotEmpty(t, h)
	assert.True(t, h.Compare("s3cr3t!"))
	assert.False(t, h.Compare("wrong"))
}

func TestHashedValueScan(t *testing.T) {
	// Empty hash serializes to NULL.
	var empty Hashed
	v, err := empty.Value()
	require.NoError(t, err)
	assert.Nil(t, v)

	// Non-empty hash serializes to its bytes.
	var h Hashed
	require.NoError(t, h.Set("pw"))
	v, err = h.Value()
	require.NoError(t, err)
	assert.Equal(t, []byte(h), v)

	// NULL scans back to an empty hash.
	var scanned Hashed
	require.NoError(t, scanned.Scan(nil))
	assert.Nil(t, []byte(scanned))

	// []byte and string round-trip.
	require.NoError(t, scanned.Scan([]byte(h)))
	assert.True(t, scanned.Compare("pw"))
	require.NoError(t, scanned.Scan(string(h)))
	assert.True(t, scanned.Compare("pw"))

	assert.Error(t, scanned.Scan(123)) // unsupported type
}

func TestVerificationIntentString(t *testing.T) {
	assert.Equal(t, "password_reset", PasswordResetIntent.String())
	assert.Equal(t, "magic_link", MagicLinkIntent.String())
	assert.Equal(t, "unknown", VerificationIntent(99).String())
}

func TestVerificationIntentJSON(t *testing.T) {
	b, err := json.Marshal(EmailVerificationIntent)
	require.NoError(t, err)
	assert.JSONEq(t, `"email_verification"`, string(b))

	var vi VerificationIntent
	require.NoError(t, json.Unmarshal([]byte(`"magic_link"`), &vi))
	assert.Equal(t, MagicLinkIntent, vi)

	assert.Error(t, json.Unmarshal([]byte(`"nope"`), &vi))
}

func TestVerificationIntentValueScan(t *testing.T) {
	dv, err := MagicLinkIntent.Value()
	require.NoError(t, err)
	assert.Equal(t, "magic_link", dv)

	_, err = VerificationIntent(99).Value()
	assert.Error(t, err)

	var vi VerificationIntent
	require.NoError(t, vi.Scan("password_reset"))
	assert.Equal(t, PasswordResetIntent, vi)
	require.NoError(t, vi.Scan([]byte("magic_link")))
	assert.Equal(t, MagicLinkIntent, vi)
	assert.Error(t, vi.Scan(123))
}

func TestSetBcryptCost(t *testing.T) {
	orig := bcryptCost
	defer func() { _ = SetBcryptCost(orig) }() // restore (also resets the dummy hash)

	assert.Error(t, SetBcryptCost(bcrypt.MinCost-1))
	assert.Error(t, SetBcryptCost(bcrypt.MaxCost+1))

	require.NoError(t, SetBcryptCost(bcrypt.MinCost))
	assert.Equal(t, bcrypt.MinCost, bcryptCost)

	// Hashing now uses the configured cost.
	var h Hashed
	require.NoError(t, h.Set("x"))
	cost, err := bcrypt.Cost([]byte(h))
	require.NoError(t, err)
	assert.Equal(t, bcrypt.MinCost, cost)
}

func TestDummyCompare(t *testing.T) {
	assert.NotPanics(t, func() { DummyCompare("anything") })
}
