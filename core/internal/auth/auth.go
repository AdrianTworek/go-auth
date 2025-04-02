package auth

import (
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	SessionDuration         = 7 * 24 * time.Hour
	SessionRefreshThreshold = SessionDuration / 2
)

const (
	SessionTokenBytes = 32
	EmailTokenBytes   = 64
)

type VerificationIntent int

const (
	PasswordResetIntent VerificationIntent = iota
	EmailVerificationIntent
	OneTimePasswordIntent
	MagicLinkIntent
)

var verificationIntentToString = map[VerificationIntent]string{
	PasswordResetIntent:     "password_reset",
	EmailVerificationIntent: "email_verification",
	OneTimePasswordIntent:   "one_time_password",
	MagicLinkIntent:         "magic_link",
}

var stringToVerificationIntent = map[string]VerificationIntent{
	"password_reset":     PasswordResetIntent,
	"email_verification": EmailVerificationIntent,
	"one_time_password":  OneTimePasswordIntent,
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

type Hashed []byte

func (p *Hashed) Set(plainText string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainText), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	*p = hash
	return nil
}

func (p *Hashed) Compare(plainText string) bool {
	return bcrypt.CompareHashAndPassword(*p, []byte(plainText)) == nil
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

func baseCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		HttpOnly: true,
		// TODO: Set to true when running in the production environment and using HTTPS
		Secure:  false,
		Value:   token,
		Expires: expiresAt,
		Name:    "session",
		Path:    "/",
	}
}

func NewSessionCookie(token string) *http.Cookie {
	return baseCookie(token, time.Now().Add(SessionDuration))
}

func DeleteSessionCookie() *http.Cookie {
	return baseCookie("", time.Now().Add(-time.Hour))
}
