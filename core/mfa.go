package core

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// defaultIssuerName is the authenticator-app label used when neither MFAConfig.Issuer
// nor a parseable BaseURL gives us something better. A user staring at a list of codes
// needs *something* to tell them apart.
const defaultIssuerName = "go-auth"

// defaultBackupCodeCount is how many recovery codes are issued at confirmation and on
// every regeneration. Ten is enough that a user is unlikely to run out before noticing
// the remaining count, and few enough to print on a card.
const defaultBackupCodeCount = 10

// resolvedMFA holds the effective two-factor settings for an AuthClient, with defaults
// applied and the encryption key already decoded, so no handler reads raw config or
// re-decodes the key per request. When enabled is false the capability does not exist:
// the routes are not mounted and no sign-in path consults it.
type resolvedMFA struct {
	enabled         bool
	key             []byte
	issuer          string
	period          time.Duration
	digits          int
	skewSteps       int
	backupCodeCount int
	oauthSatisfies  bool
}

// resolveMFA validates and defaults the two-factor configuration. A nil config yields a
// disabled capability and no error — that is the default, and it must stay free of any
// new obligation on the consumer.
func resolveMFA(cfg *MFAConfig, baseURL string) (resolvedMFA, error) {
	if cfg == nil {
		return resolvedMFA{}, nil
	}

	key, err := resolveEncryptionKey(cfg.EncryptionKey)
	if err != nil {
		return resolvedMFA{}, err
	}

	m := resolvedMFA{
		enabled:         true,
		key:             key,
		issuer:          cfg.Issuer,
		period:          auth.DefaultTOTPPeriod,
		digits:          auth.DefaultTOTPDigits,
		skewSteps:       auth.DefaultTOTPSkewSteps,
		backupCodeCount: defaultBackupCodeCount,
		oauthSatisfies:  cfg.OAuthSatisfiesSecondFactor,
	}

	if m.issuer == "" {
		m.issuer = defaultIssuer(baseURL)
	}
	if cfg.Period > 0 {
		m.period = cfg.Period
	}
	if cfg.Digits > 0 {
		m.digits = cfg.Digits
	}
	// Zero means "use the default", so a negative value is how an operator asks for no
	// skew at all — the same convention Limit.Max already uses to disable a dimension.
	if cfg.SkewSteps != 0 {
		m.skewSteps = max(cfg.SkewSteps, 0)
	}
	if cfg.BackupCodeCount > 0 {
		m.backupCodeCount = cfg.BackupCodeCount
	}

	return m, nil
}

// resolveEncryptionKey accepts the key in either of the two forms a consumer is likely
// to have: the hex string `openssl rand -hex 32` prints, or 32 raw bytes.
//
// The two cannot be confused. 64 raw bytes is not a valid AES-256 key in the first
// place, so a 64-character input that parses as hex is unambiguously hex, and anything
// else of that length is an error rather than a silent reinterpretation.
func resolveEncryptionKey(key string) ([]byte, error) {
	hexLen := hex.EncodedLen(auth.EncryptionKeyBytes)

	if len(key) == hexLen {
		if decoded, err := hex.DecodeString(key); err == nil {
			return decoded, nil
		}
	}
	if len(key) == auth.EncryptionKeyBytes {
		return []byte(key), nil
	}

	if key == "" {
		return nil, fmt.Errorf(
			"MFA.EncryptionKey is required when MFA is enabled: supply %d hex characters (generate one with `openssl rand -hex %d`) or exactly %d raw bytes",
			hexLen, auth.EncryptionKeyBytes, auth.EncryptionKeyBytes,
		)
	}
	return nil, fmt.Errorf(
		"MFA.EncryptionKey must be %d hex characters (generate one with `openssl rand -hex %d`) or exactly %d raw bytes, got %d characters",
		hexLen, auth.EncryptionKeyBytes, auth.EncryptionKeyBytes, len(key),
	)
}

func defaultIssuer(baseURL string) string {
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return defaultIssuerName
}

// CanUseMFA reports whether two-factor authentication is configured. Adapters gate route
// mounting on it, exactly as they do with CanLoginWithOAuth and CanLoginWithMagicLink: a
// consumer who has not opted in serves no second-factor surface at all, rather than
// endpoints that answer "not configured".
func (c *AuthClient) CanUseMFA() bool {
	return c.mfa.enabled
}

// warnIfMFADowngraded logs loudly when the capability is switched off while users are
// still enrolled, because that silently drops each of them to a single factor.
//
// There is no honest way to keep honouring an enrolment without the encryption key, so
// the mitigation is visibility rather than refusal: rolling back deliberately is
// legitimate, and failing to start would be a worse outcome than the downgrade.
//
// One indexed existence check, once per process — not per request.
func warnIfMFADowngraded(ctx context.Context, s *store.Storage) {
	exists, err := s.TOTP.ExistsConfirmed(ctx)
	if err != nil {
		// Overwhelmingly the likely cause is that migration 000006 has not been run
		// yet, which is a perfectly normal state for a consumer upgrading the library.
		// Failing — or even warning — here would turn a pending migration into a
		// startup crash loop.
		slog.Debug("skipped the two-factor enrolment check", "error", err)
		return
	}
	if !exists {
		return
	}

	slog.Warn(
		"two-factor authentication is not configured, but users are still enrolled: " +
			"they have been silently downgraded to a single factor. Verifying their codes " +
			"is impossible without AuthConfig.MFA.EncryptionKey. Restore the configuration, " +
			"or have those users re-enrol once it is back.",
	)
}
