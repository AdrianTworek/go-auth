package auth

import (
	"crypto/sha1" // #nosec G505 -- exercising the RFC's SHA-1 test vectors
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The seeds RFC 6238 Appendix B publishes alongside its test vectors: the ASCII string
// "12345678901234567890", repeated and truncated to each variant's block size.
const (
	rfcSeedSHA1   = "12345678901234567890"
	rfcSeedSHA256 = "12345678901234567890123456789012"
	rfcSeedSHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

// Test_GenerateTOTP_RFC6238Vectors is the conformance test for the generator. The
// expected values are RFC 6238's own published table, not output recorded from this
// implementation, so it demonstrates agreement with the specification rather than with
// itself — which is what would catch a byte-order or truncation-mask mistake that a
// round trip against our own code never could.
//
// The RFC tabulates 8-digit codes across three HMAC variants and six timestamps, at the
// default 30-second period. Production uses SHA-1 at 6 digits; the parameters exist so
// the whole table can be exercised.
func Test_GenerateTOTP_RFC6238Vectors(t *testing.T) {
	const period = 30 * time.Second

	variants := []struct {
		name string
		seed string
		alg  func() hash.Hash
	}{
		{"SHA1", rfcSeedSHA1, sha1.New},
		{"SHA256", rfcSeedSHA256, sha256.New},
		{"SHA512", rfcSeedSHA512, sha512.New},
	}

	// One row per timestamp, columns in the same order as variants above.
	vectors := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, v := range vectors {
		expected := map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512}
		step := TOTPStep(time.Unix(v.unix, 0), period)

		for _, variant := range variants {
			t.Run(variant.name+"/T="+time.Unix(v.unix, 0).UTC().Format(time.RFC3339), func(t *testing.T) {
				got := GenerateTOTP([]byte(variant.seed), step, 8, variant.alg)
				assert.Equal(t, expected[variant.name], got,
					"RFC 6238 vector: %s at unix %d (step %d)", variant.name, v.unix, step)
			})
		}
	}
}

// Test_TOTPStep checks the counter itself against the step numbers the RFC tabulates in
// hex alongside each timestamp.
func Test_TOTPStep(t *testing.T) {
	const period = 30 * time.Second

	assert.Equal(t, int64(0x1), TOTPStep(time.Unix(59, 0), period))
	assert.Equal(t, int64(0x23523EC), TOTPStep(time.Unix(1111111109, 0), period))
	assert.Equal(t, int64(0x23523ED), TOTPStep(time.Unix(1111111111, 0), period))
	assert.Equal(t, int64(0x273EF07), TOTPStep(time.Unix(1234567890, 0), period))
	assert.Equal(t, int64(0x3F940AA), TOTPStep(time.Unix(2000000000, 0), period))
	assert.Equal(t, int64(0x27BC86AA), TOTPStep(time.Unix(20000000000, 0), period))

	// A period of zero falls back to the default rather than dividing by zero.
	assert.Equal(t, TOTPStep(time.Unix(59, 0), DefaultTOTPPeriod), TOTPStep(time.Unix(59, 0), 0))
}

// Test_GenerateTOTP_ZeroPads guards the formatting rather than the arithmetic: a
// truncation result shorter than the requested width has to be left-padded, or a code
// would occasionally be five digits long and rejected by the comparison in VerifyTOTP.
func Test_GenerateTOTP_ZeroPads(t *testing.T) {
	secret := []byte(rfcSeedSHA1)

	// Search for a step whose 6-digit code needs padding; with a uniform remainder one
	// step in ten qualifies, so this terminates almost immediately.
	var padded string
	for step := int64(0); step < 1000; step++ {
		code := GenerateTOTP(secret, step, 6, sha1.New)
		if strings.HasPrefix(code, "0") {
			padded = code
			break
		}
	}

	require.NotEmpty(t, padded, "expected to find a code requiring zero-padding")
	assert.Len(t, padded, 6)
}

func Test_VerifyTOTP_AcceptsCurrentStep(t *testing.T) {
	secret, err := NewTOTPSecret()
	require.NoError(t, err)

	now := time.Unix(1700000000, 0)
	code := GenerateTOTP(secret, TOTPStep(now, DefaultTOTPPeriod), DefaultTOTPDigits, sha1.New)

	step, ok := VerifyTOTP(secret, code, now, DefaultTOTPPeriod, DefaultTOTPDigits, 0)
	require.True(t, ok)
	assert.Equal(t, TOTPStep(now, DefaultTOTPPeriod), step)
}

// Test_VerifyTOTP_Skew is the usability guarantee: a phone whose clock is a little off
// still works. The returned step identifies which window matched, which is what the
// replay guard records.
func Test_VerifyTOTP_Skew(t *testing.T) {
	secret, err := NewTOTPSecret()
	require.NoError(t, err)

	now := time.Unix(1700000000, 0)
	current := TOTPStep(now, DefaultTOTPPeriod)

	codeFor := func(step int64) string {
		return GenerateTOTP(secret, step, DefaultTOTPDigits, sha1.New)
	}

	t.Run("adjacent steps accepted at skew 1", func(t *testing.T) {
		for _, delta := range []int64{-1, 0, 1} {
			step, ok := VerifyTOTP(secret, codeFor(current+delta), now, DefaultTOTPPeriod, DefaultTOTPDigits, 1)
			assert.True(t, ok, "delta %d should be accepted", delta)
			assert.Equal(t, current+delta, step)
		}
	})

	t.Run("two steps out rejected at skew 1", func(t *testing.T) {
		for _, delta := range []int64{-2, 2} {
			_, ok := VerifyTOTP(secret, codeFor(current+delta), now, DefaultTOTPPeriod, DefaultTOTPDigits, 1)
			assert.False(t, ok, "delta %d should be rejected", delta)
		}
	})

	t.Run("no skew accepts only the current step", func(t *testing.T) {
		_, ok := VerifyTOTP(secret, codeFor(current+1), now, DefaultTOTPPeriod, DefaultTOTPDigits, 0)
		assert.False(t, ok)
	})
}

func Test_VerifyTOTP_Rejects(t *testing.T) {
	secret, err := NewTOTPSecret()
	require.NoError(t, err)
	now := time.Unix(1700000000, 0)

	t.Run("wrong code", func(t *testing.T) {
		_, ok := VerifyTOTP(secret, "000000", now, DefaultTOTPPeriod, DefaultTOTPDigits, 1)
		// A fixed wrong guess has a 3-in-a-million chance of being right; if this ever
		// flakes, the odds say to buy a lottery ticket rather than change the test.
		assert.False(t, ok)
	})

	t.Run("wrong length", func(t *testing.T) {
		code := GenerateTOTP(secret, TOTPStep(now, DefaultTOTPPeriod), DefaultTOTPDigits, sha1.New)
		_, ok := VerifyTOTP(secret, code+"1", now, DefaultTOTPPeriod, DefaultTOTPDigits, 1)
		assert.False(t, ok)
	})

	t.Run("another secret", func(t *testing.T) {
		other, err := NewTOTPSecret()
		require.NoError(t, err)
		code := GenerateTOTP(other, TOTPStep(now, DefaultTOTPPeriod), DefaultTOTPDigits, sha1.New)
		_, ok := VerifyTOTP(secret, code, now, DefaultTOTPPeriod, DefaultTOTPDigits, 1)
		assert.False(t, ok)
	})
}

func Test_NewTOTPSecret(t *testing.T) {
	first, err := NewTOTPSecret()
	require.NoError(t, err)
	second, err := NewTOTPSecret()
	require.NoError(t, err)

	assert.Len(t, first, TOTPSecretBytes)
	assert.NotEqual(t, first, second)
}

// Test_OTPAuthURI covers the two things a consumer cannot fix from the outside: the
// secret has to decode as unpadded base32, and the label's separator has to survive an
// issuer that contains the separator itself.
func Test_OTPAuthURI(t *testing.T) {
	secret := []byte(rfcSeedSHA1)
	uri := OTPAuthURI("Acme Corp: Staging", "user@example.com", secret, 6, 30*time.Second)

	assert.True(t, strings.HasPrefix(uri, "otpauth://totp/"), "got %q", uri)

	parsed, err := url.Parse(uri)
	require.NoError(t, err)
	assert.Equal(t, "totp", parsed.Host)

	t.Run("secret decodes without padding", func(t *testing.T) {
		encoded := parsed.Query().Get("secret")
		assert.NotContains(t, encoded, "=")

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, secret, decoded)
	})

	t.Run("label separator survives a colon in the issuer", func(t *testing.T) {
		// Exactly one unescaped colon: the separator between issuer and account.
		label := strings.TrimPrefix(parsed.EscapedPath(), "/")
		assert.Equal(t, 1, strings.Count(label, ":"), "label %q", label)

		issuer, account, found := strings.Cut(label, ":")
		require.True(t, found)

		unescapedIssuer, err := url.PathUnescape(issuer)
		require.NoError(t, err)
		assert.Equal(t, "Acme Corp: Staging", unescapedIssuer)

		unescapedAccount, err := url.PathUnescape(account)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", unescapedAccount)
	})

	t.Run("parameters an authenticator app reads", func(t *testing.T) {
		q := parsed.Query()
		assert.Equal(t, "Acme Corp: Staging", q.Get("issuer"))
		assert.Equal(t, "SHA1", q.Get("algorithm"))
		assert.Equal(t, "6", q.Get("digits"))
		assert.Equal(t, "30", q.Get("period"))
	})
}
