package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// backupCodeAlphabet is Crockford's base32 alphabet: the digits and the upper-case
// letters, minus I, L, O and U. The first three are excluded because they are
// indistinguishable from 1 and 0 in most fonts, and U because dropping it avoids
// generating unfortunate words. A user reading a code off paper and typing it into a
// login form is the whole use case, so legibility is a security property here.
const backupCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	// backupCodeGroups and backupCodeGroupLen shape a code as two hyphenated groups of
	// five, e.g. "3KD9F-7QMXB". Ten characters from a 32-symbol alphabet is 50 bits of
	// entropy, which is why these are hashed with SHA-256 rather than bcrypt: there is
	// no dictionary to run against a value the library generated.
	backupCodeGroups   = 2
	backupCodeGroupLen = 5
)

// NewBackupCode returns one single-use recovery code in its display form.
func NewBackupCode() (string, error) {
	raw := make([]byte, backupCodeGroups*backupCodeGroupLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate backup code: %w", err)
	}

	var b strings.Builder
	b.Grow(len(raw) + backupCodeGroups - 1)
	for i, v := range raw {
		if i > 0 && i%backupCodeGroupLen == 0 {
			b.WriteByte('-')
		}
		// 256 is an exact multiple of the 32-symbol alphabet, so the modulo introduces
		// no bias and rejection sampling is unnecessary.
		b.WriteByte(backupCodeAlphabet[int(v)%len(backupCodeAlphabet)])
	}
	return b.String(), nil
}

// NormalizeBackupCode reduces a code as typed to the canonical form that is hashed and
// stored, so that the hyphen, incidental whitespace and letter case do not decide
// whether a user can get into their account.
//
// It also folds the characters Crockford's alphabet omits onto the ones they are
// mistaken for — O to zero, I and L to one — which is the point of choosing that
// alphabet: a code can never legitimately contain them, so a user who typed one meant
// the digit.
func NormalizeBackupCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			b.WriteByte('0')
		case 'I', 'L':
			b.WriteByte('1')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
