package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultSessionDuration is the fallback session lifetime used when
	// SessionConfig.Duration is left unset.
	DefaultSessionDuration = 7 * 24 * time.Hour
	// DefaultTokenDuration is the fallback lifetime for emailed single-use tokens
	// (email verification, password reset, magic link) when the matching
	// TokenConfig field is left unset.
	DefaultTokenDuration = 5 * time.Minute

	SessionTokenBytes = 32
	EmailTokenBytes   = 64
)

type VerificationIntent int

const (
	PasswordResetIntent VerificationIntent = iota
	EmailVerificationIntent
	MagicLinkIntent
)

var verificationIntentToString = map[VerificationIntent]string{
	PasswordResetIntent:     "password_reset",
	EmailVerificationIntent: "email_verification",
	MagicLinkIntent:         "magic_link",
}

var stringToVerificationIntent = map[string]VerificationIntent{
	"password_reset":     PasswordResetIntent,
	"email_verification": EmailVerificationIntent,
	"magic_link":         MagicLinkIntent,
}

func (v VerificationIntent) String() string {
	if str, ok := verificationIntentToString[v]; ok {
		return str
	}
	return "unknown"
}

func (v VerificationIntent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *VerificationIntent) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	intent, ok := stringToVerificationIntent[str]
	if !ok {
		return errors.New("invalid VerificationIntent value")
	}

	*v = intent
	return nil
}

func (v VerificationIntent) Value() (driver.Value, error) {
	str := v.String()
	if str == "unknown" {
		return "", errors.New("invalid VerificationIntent value")
	}
	return str, nil
}

func (v *VerificationIntent) Scan(value interface{}) error {
	switch i := value.(type) {
	case string:
		*v = stringToVerificationIntent[i]
		return nil
	case []byte:
		*v = stringToVerificationIntent[string(i)]
		return nil
	default:
		return errors.New("invalid VerificationIntent scan source")
	}
}

// Custom type to handle JSON null properly
type NullString struct {
	sql.NullString
}

func (ns NullString) MarshalJSON() ([]byte, error) {
	if !ns.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(ns.String)
}

func (ns *NullString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		ns.String = ""
		ns.Valid = false
		return nil
	}
	ns.Valid = true
	return json.Unmarshal(data, &ns.String)
}

func (ns *NullString) Scan(value interface{}) error {
	return ns.NullString.Scan(value)
}

func (ns NullString) Value() (driver.Value, error) {
	return ns.NullString.Value()
}

func NewNullString(s string) *NullString {
	return &NullString{sql.NullString{String: s, Valid: s != ""}}
}

// bcryptCost is the work factor used for password hashing. Tune it via
// SetBcryptCost (e.g. from AuthConfig.BcryptCost).
var bcryptCost = bcrypt.DefaultCost

// SetBcryptCost updates the bcrypt work factor used for hashing passwords and
// regenerates the timing-equalization hash so DummyCompare stays in sync. It
// returns an error if cost is outside bcrypt's valid range.
func SetBcryptCost(cost int) error {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	bcryptCost = cost
	dummyPasswordHash = mustGenerateDummyHash(cost)
	return nil
}

type Hashed []byte

func (p *Hashed) Set(plainText string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainText), bcryptCost)
	if err != nil {
		return err
	}

	*p = hash
	return nil
}

func (p *Hashed) Compare(plainText string) bool {
	return bcrypt.CompareHashAndPassword(*p, []byte(plainText)) == nil
}

// Value implements driver.Valuer so an empty hash (e.g. an OAuth-only user with no
// password) is stored as SQL NULL rather than an empty byte array.
func (p Hashed) Value() (driver.Value, error) {
	if len(p) == 0 {
		return nil, nil
	}
	return []byte(p), nil
}

// Scan implements sql.Scanner, mapping a NULL password back to an empty hash.
func (p *Hashed) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*p = nil
	case []byte:
		*p = append(Hashed(nil), v...)
	case string:
		*p = Hashed(v)
	default:
		return fmt.Errorf("cannot scan %T into Hashed", value)
	}
	return nil
}

// dummyPasswordHash is a valid bcrypt hash (at the same cost as real passwords)
// used solely to spend comparable CPU time on the user-not-found login path.
var dummyPasswordHash = mustGenerateDummyHash(bcryptCost)

func mustGenerateDummyHash(cost int) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("timing-equalization-password"), cost)
	if err != nil {
		// Unreachable for a short, fixed password at a valid cost.
		panic(err)
	}
	return hash
}

// DummyCompare performs a throwaway bcrypt comparison so that authentication
// takes a similar amount of time whether or not the user exists, mitigating
// user enumeration via response timing.
func DummyCompare(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
}

func GenerateSecureToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("token length must be greater than 0")
	}

	token := make([]byte, n)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(token), nil
}

// HashToken returns the hex-encoded SHA-256 of a token. Session and verification
// tokens are high-entropy random values, so a fast hash (not bcrypt) is the correct
// choice: we store only the hash and look it up by equality, so a database leak
// exposes no usable credentials.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CookieOptions configures the security-relevant attributes of the session cookie.
type CookieOptions struct {
	Name     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

func baseCookie(token string, expiresAt time.Time, opts CookieOptions) *http.Cookie {
	// #nosec G124 -- Secure is configurable via SessionConfig.CookieSecure and defaults to true; gosec can't prove the value through the variable
	return &http.Cookie{
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
		Domain:   opts.Domain,
		Value:    token,
		Expires:  expiresAt,
		Name:     opts.Name,
		Path:     "/",
	}
}

func NewSessionCookie(token string, expiresAt time.Time, opts CookieOptions) *http.Cookie {
	return baseCookie(token, expiresAt, opts)
}

func DeleteSessionCookie(opts CookieOptions) *http.Cookie {
	return baseCookie("", time.Now().Add(-time.Hour), opts)
}
