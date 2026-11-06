package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 defines TOTP in terms of HMAC-SHA-1; authenticator apps implement nothing else
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// TOTPSecretBytes is the length of a generated TOTP shared secret. RFC 4226
	// recommends at least 128 bits and 160 for HMAC-SHA-1; 20 bytes is also what
	// every mainstream authenticator app expects, and it base32-encodes to a
	// 32-character string a user can retype by hand.
	TOTPSecretBytes = 20

	// DefaultTOTPPeriod, DefaultTOTPDigits and DefaultTOTPSkewSteps are the values
	// the library uses unless MFAConfig overrides them. The first two are fixed by
	// what authenticator apps implement rather than chosen.
	DefaultTOTPPeriod    = 30 * time.Second
	DefaultTOTPDigits    = 6
	DefaultTOTPSkewSteps = 1

	// maxTOTPDigits is the largest code length the truncation arithmetic can
	// represent: dynamic truncation yields 31 bits, so ten digits is the ceiling.
	maxTOTPDigits = 10
)

// base32NoPadding is the encoding authenticator apps expect for the secret in an
// otpauth:// URI. Padding is omitted because several popular apps reject '=' in the
// secret parameter outright.
var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh random TOTP shared secret.
func NewTOTPSecret() ([]byte, error) {
	secret := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return secret, nil
}

// EncodeTOTPSecret renders a secret in the base32 form a user types into an
// authenticator app that cannot scan a QR code.
func EncodeTOTPSecret(secret []byte) string {
	return base32NoPadding.EncodeToString(secret)
}

// TOTPStep returns the RFC 6238 time-step counter for an instant: the number of whole
// periods since the Unix epoch. A period of zero or less falls back to the default.
func TOTPStep(t time.Time, period time.Duration) int64 {
	if period <= 0 {
		period = DefaultTOTPPeriod
	}
	seconds := int64(period / time.Second)
	if seconds <= 0 {
		seconds = int64(DefaultTOTPPeriod / time.Second)
	}
	return t.Unix() / seconds
}

// GenerateTOTP computes the RFC 6238 one-time password for a given time step.
//
// The construction is a big-endian counter, an HMAC, and RFC 4226's dynamic
// truncation: the low nibble of the final byte selects a four-byte window, the top bit
// of which is masked off so the result is sign-agnostic across implementations, and the
// remainder modulo 10^digits is the code. The cryptography is entirely stdlib; the rest
// is arithmetic, which is why implementing the specification in-house is reasonable
// where rolling a primitive would not be.
//
// digits must be between 1 and maxTOTPDigits and is clamped if it is not — returning a
// string of the wrong length would be worse than correcting it, and the configuration
// that reaches here is already validated.
//
// alg selects the HMAC hash. Production always passes sha1.New, because that is what
// authenticator apps implement; the parameter exists so the generator can be exercised
// against the SHA-256 and SHA-512 columns of RFC 6238's test vectors, which is what
// makes conformance demonstrable rather than assumed.
func GenerateTOTP(secret []byte, step int64, digits int, alg func() hash.Hash) string {
	if digits < 1 {
		digits = DefaultTOTPDigits
	}
	if digits > maxTOTPDigits {
		digits = maxTOTPDigits
	}

	var counter [8]byte
	// The RFC's counter is the step as an unsigned 64-bit big-endian value, so the
	// reinterpretation is the specification, not a lossy conversion. A step is only
	// negative for an instant before 1970, which no clock a caller passes will produce.
	binary.BigEndian.PutUint64(counter[:], uint64(step)) // #nosec G115 -- RFC 6238 counter is an unsigned 64-bit reinterpretation of the step

	mac := hmac.New(alg, secret)
	// hash.Hash.Write never returns an error.
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	modulus := uint64(1)
	for range digits {
		modulus *= 10
	}

	return fmt.Sprintf("%0*d", digits, uint64(truncated)%modulus)
}

// VerifyTOTP reports whether code is a valid one-time password at the given instant,
// and returns the time step that matched.
//
// skewSteps accepts codes from that many steps either side of the current one, because
// phone clocks drift. The matched step is returned so the caller can record it and
// refuse the same code a second time within its validity window — knowing a code is
// arithmetically correct is not the same as knowing it has not already been spent, and
// the replay guard needs both.
//
// The comparison is constant-time. The loop returns as soon as a step matches, which
// leaks which step it was through timing; that is not a secret, since it follows from
// the clock.
func VerifyTOTP(secret []byte, code string, at time.Time, period time.Duration, digits, skewSteps int) (int64, bool) {
	if len(code) != digits {
		return 0, false
	}
	if skewSteps < 0 {
		skewSteps = 0
	}

	current := TOTPStep(at, period)
	for delta := -skewSteps; delta <= skewSteps; delta++ {
		step := current + int64(delta)
		candidate := GenerateTOTP(secret, step, digits, sha1.New)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// OTPAuthURI builds the otpauth:// URI an authenticator app consumes, usually by way of
// a QR code the consumer renders. Rendering the image is deliberately not the library's
// job; handing over the URI is.
//
// issuer names the service in the app's list, accountName identifies the user within it
// (conventionally their email address). Both appear in the label, where the colon is the
// field separator, so a colon inside either part is percent-encoded rather than left to
// be misread as a separator.
func OTPAuthURI(issuer, accountName string, secret []byte, digits int, period time.Duration) string {
	if period <= 0 {
		period = DefaultTOTPPeriod
	}

	query := url.Values{}
	query.Set("secret", EncodeTOTPSecret(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(digits))
	query.Set("period", strconv.Itoa(int(period/time.Second)))

	label := escapeLabelPart(issuer) + ":" + escapeLabelPart(accountName)
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// escapeLabelPart percent-encodes one half of an otpauth label. url.PathEscape leaves a
// colon alone, since RFC 3986 permits it in a path segment, but here the colon is the
// label's own separator — so it has to go.
func escapeLabelPart(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}
