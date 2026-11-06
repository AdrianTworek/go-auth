package core

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// testHexKey is a 64-character hex key, the form `openssl rand -hex 32` prints.
const testHexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func Test_ResolveEncryptionKey(t *testing.T) {
	t.Run("accepts 64 hex characters", func(t *testing.T) {
		key, err := resolveEncryptionKey(testHexKey)
		require.NoError(t, err)
		assert.Len(t, key, auth.EncryptionKeyBytes)

		expected, err := hex.DecodeString(testHexKey)
		require.NoError(t, err)
		assert.Equal(t, expected, key)
	})

	t.Run("accepts upper-case hex", func(t *testing.T) {
		key, err := resolveEncryptionKey(strings.ToUpper(testHexKey))
		require.NoError(t, err)
		assert.Len(t, key, auth.EncryptionKeyBytes)
	})

	t.Run("accepts 32 raw bytes", func(t *testing.T) {
		raw := strings.Repeat("k", auth.EncryptionKeyBytes)
		key, err := resolveEncryptionKey(raw)
		require.NoError(t, err)
		assert.Equal(t, []byte(raw), key)
	})

	// 32 characters of hex would be an AES-128 key, which is not what this field is
	// for — so it is taken as 32 raw bytes, which is the only reading that yields a
	// usable key.
	t.Run("a 32-character hex string is taken as raw bytes", func(t *testing.T) {
		key, err := resolveEncryptionKey(testHexKey[:32])
		require.NoError(t, err)
		assert.Equal(t, []byte(testHexKey[:32]), key)
	})

	t.Run("rejects a missing key and says how to make one", func(t *testing.T) {
		_, err := resolveEncryptionKey("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
		assert.Contains(t, err.Error(), "openssl rand -hex 32")
	})

	t.Run("rejects the wrong length and names both accepted forms", func(t *testing.T) {
		for _, bad := range []string{
			strings.Repeat("a", 31),
			strings.Repeat("a", 33),
			strings.Repeat("a", 63),
			strings.Repeat("a", 65),
			strings.Repeat("a", 128),
		} {
			_, err := resolveEncryptionKey(bad)
			require.Error(t, err, "length %d", len(bad))
			assert.Contains(t, err.Error(), "64 hex characters")
			assert.Contains(t, err.Error(), "32 raw bytes")
		}
	})

	// 64 characters that are not hex cannot be reinterpreted as raw bytes, because 64
	// raw bytes is not a valid AES-256 key either.
	t.Run("rejects 64 non-hex characters", func(t *testing.T) {
		_, err := resolveEncryptionKey(strings.Repeat("z", 64))
		assert.Error(t, err)
	})
}

func Test_ResolveMFA(t *testing.T) {
	t.Run("nil config is disabled and requires nothing", func(t *testing.T) {
		m, err := resolveMFA(nil, "")
		require.NoError(t, err)
		assert.False(t, m.enabled)
		assert.Nil(t, m.key)
	})

	t.Run("applies defaults", func(t *testing.T) {
		m, err := resolveMFA(&MFAConfig{EncryptionKey: testHexKey}, "https://app.example.com")
		require.NoError(t, err)

		assert.True(t, m.enabled)
		assert.Len(t, m.key, auth.EncryptionKeyBytes)
		// Asserted as literals, so changing a constant can't quietly change the policy.
		assert.Equal(t, 30*time.Second, m.period)
		assert.Equal(t, 6, m.digits)
		assert.Equal(t, 1, m.skewSteps)
		assert.Equal(t, 10, m.backupCodeCount)
		assert.False(t, m.oauthSatisfies, "OAuth must be challenged unless explicitly exempted")
	})

	t.Run("honours overrides", func(t *testing.T) {
		m, err := resolveMFA(&MFAConfig{
			EncryptionKey:              testHexKey,
			Issuer:                     "Acme",
			Period:                     60 * time.Second,
			Digits:                     8,
			SkewSteps:                  2,
			BackupCodeCount:            4,
			OAuthSatisfiesSecondFactor: true,
		}, "https://app.example.com")
		require.NoError(t, err)

		assert.Equal(t, "Acme", m.issuer)
		assert.Equal(t, 60*time.Second, m.period)
		assert.Equal(t, 8, m.digits)
		assert.Equal(t, 2, m.skewSteps)
		assert.Equal(t, 4, m.backupCodeCount)
		assert.True(t, m.oauthSatisfies)
	})

	// Zero means "use the default", so a negative value is the only way to ask for no
	// skew — the convention Limit.Max already uses to disable a dimension.
	t.Run("a negative skew accepts only the current step", func(t *testing.T) {
		m, err := resolveMFA(&MFAConfig{EncryptionKey: testHexKey, SkewSteps: -1}, "")
		require.NoError(t, err)
		assert.Equal(t, 0, m.skewSteps)
	})

	t.Run("propagates a bad key", func(t *testing.T) {
		_, err := resolveMFA(&MFAConfig{EncryptionKey: "too-short"}, "")
		assert.Error(t, err)
	})
}

func Test_DefaultIssuer(t *testing.T) {
	assert.Equal(t, "app.example.com", defaultIssuer("https://app.example.com"))
	assert.Equal(t, "app.example.com:8080", defaultIssuer("http://app.example.com:8080/api"))
	assert.Equal(t, defaultIssuerName, defaultIssuer(""))
	assert.Equal(t, defaultIssuerName, defaultIssuer("not a url"))

	t.Run("falls back rather than naming an empty service", func(t *testing.T) {
		// A user reading a list of codes needs something to tell them apart, so an
		// unusable BaseURL must not produce a blank label.
		assert.NotEmpty(t, defaultIssuer("://broken"))
	})
}

func Test_ResolveRateLimitRules_MFAVerify(t *testing.T) {
	t.Run("defaults are tighter than login", func(t *testing.T) {
		rl := resolveRateLimitRules(nil)

		assert.Equal(t, 20, rl.mfaVerify.perIP.limit)
		assert.Equal(t, 15*time.Minute, rl.mfaVerify.perIP.window)
		assert.Equal(t, 10, rl.mfaVerify.perAccount.limit)
		assert.Equal(t, 15*time.Minute, rl.mfaVerify.perAccount.window)

		// A six-digit code has a far smaller space than a password, so its window must
		// not be more generous than the password step's.
		assert.LessOrEqual(t, rl.mfaVerify.perAccount.window, rl.login.perAccount.window)
	})

	t.Run("honours an override and a disabled dimension", func(t *testing.T) {
		rl := resolveRateLimitRules(&RateLimitConfig{
			MFAVerify: Rule{
				PerIP:      Limit{Max: 3, Window: time.Minute},
				PerAccount: Limit{Max: -1},
			},
		})

		assert.Equal(t, 3, rl.mfaVerify.perIP.limit)
		assert.Equal(t, time.Minute, rl.mfaVerify.perIP.window)
		assert.False(t, rl.mfaVerify.perAccount.enabled())
	})
}

// Test_NewAuthClient_RejectsMFAWithoutKey asserts the check runs before any resource is
// opened: the DSN here is unusable, so reaching the database at all would surface a
// different error.
func Test_NewAuthClient_RejectsMFAWithoutKey(t *testing.T) {
	_, err := NewAuthClient(&AuthConfig{
		Db:      &DatabaseConfig{Dsn: "postgres://nobody@127.0.0.1:1/nothing?sslmode=disable"},
		BaseURL: "http://localhost",
		MFA:     &MFAConfig{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MFA.EncryptionKey")
}

func Test_Integration_NewAuthClient_AcceptsMFAKey(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	ac, err := NewAuthClient(&AuthConfig{
		Db:      &DatabaseConfig{Dsn: app.env.DSN},
		BaseURL: "http://localhost",
		MFA:     &MFAConfig{EncryptionKey: testHexKey},
	})
	require.NoError(t, err)
	assert.True(t, ac.CanUseMFA())
}

func Test_Integration_CanUseMFA_FalseWhenUnconfigured(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	ac, err := NewAuthClient(&AuthConfig{
		Db:      &DatabaseConfig{Dsn: app.env.DSN},
		BaseURL: "http://localhost",
	})
	require.NoError(t, err)
	assert.False(t, ac.CanUseMFA())
}

// Test_NewAuthClient_RequiresMagicLinkMFARedirect covers the combination the spec did
// not settle: magic-link completion ends in a redirect, so there is no body to carry a
// challenge in. A consumer enabling both features without naming a page for it should
// find out at startup, not when a user with a second factor is handed a cookieless
// success page.
func Test_NewAuthClient_RequiresMagicLinkMFARedirect(t *testing.T) {
	// An unusable DSN, so reaching the database at all would surface a different error:
	// this check must run before any resource is opened.
	newClient := func(session *SessionConfig) error {
		_, err := NewAuthClient(&AuthConfig{
			Db:      &DatabaseConfig{Dsn: "postgres://nobody@127.0.0.1:1/nothing?sslmode=disable"},
			BaseURL: "http://localhost",
			Session: session,
			MFA:     &MFAConfig{EncryptionKey: testHexKey},
		})
		return err
	}

	magicLink := func() *SessionConfig {
		return &SessionConfig{
			MagicLinkSuccessfulRedirectURL: "http://localhost/success",
			MagicLinkFailedRedirectURL:     "http://localhost/failed",
		}
	}

	t.Run("refused when magic-link is on and no MFA page is named", func(t *testing.T) {
		err := newClient(magicLink())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MagicLinkMFARedirectURL")
	})

	t.Run("accepted once it is named", func(t *testing.T) {
		session := magicLink()
		session.MagicLinkMFARedirectURL = "http://localhost/mfa"
		// Only the DSN should stop it now.
		err := newClient(session)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "MagicLinkMFARedirectURL")
	})

	t.Run("irrelevant when magic-link is not configured", func(t *testing.T) {
		err := newClient(&SessionConfig{})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "MagicLinkMFARedirectURL")
	})
}

// captureLogs swaps the default slog handler for the duration of a test and returns the
// buffer it writes to.
func captureLogs(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// Test_Integration_WarnsWhenMFADisabledButUsersEnrolled covers the downgrade the library
// cannot prevent. Switching the capability off takes the encryption key with it, so
// enrolled users silently drop to a single factor; the mitigation the spec chose is
// visibility, not refusal.
func Test_Integration_WarnsWhenMFADisabledButUsersEnrolled(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)

	newClientWithoutMFA := func() error {
		_, err := NewAuthClient(&AuthConfig{
			Db:      &DatabaseConfig{Dsn: app.env.DSN},
			BaseURL: "http://localhost",
		})
		return err
	}

	t.Run("silent when nobody is enrolled", func(t *testing.T) {
		logs := captureLogs(t, slog.LevelWarn)
		require.NoError(t, newClientWithoutMFA())
		assert.NotContains(t, logs.String(), "still enrolled")
	})

	t.Run("silent for an unconfirmed enrolment", func(t *testing.T) {
		require.NoError(t, app.storage.TOTP.Upsert(t.Context(), nil, &store.TOTPCredential{
			UserID: uid,
			Secret: []byte("ciphertext"),
			Nonce:  []byte("nonce-value-1"),
		}))

		logs := captureLogs(t, slog.LevelWarn)
		require.NoError(t, newClientWithoutMFA())
		assert.NotContains(t, logs.String(), "still enrolled",
			"nobody is downgraded by an enrolment that was never activated")
	})

	t.Run("warns loudly once the factor is active", func(t *testing.T) {
		require.NoError(t, app.storage.TOTP.Confirm(t.Context(), nil, uid, time.Now().UTC()))

		logs := captureLogs(t, slog.LevelWarn)
		require.NoError(t, newClientWithoutMFA(), "a deliberate rollback must still start")

		output := logs.String()
		assert.Contains(t, output, "level=WARN")
		assert.Contains(t, output, "still enrolled")
		assert.Contains(t, output, "EncryptionKey", "the warning should say what is missing")
	})

	t.Run("stays quiet when the capability is configured", func(t *testing.T) {
		logs := captureLogs(t, slog.LevelWarn)
		_, err := NewAuthClient(&AuthConfig{
			Db:      &DatabaseConfig{Dsn: app.env.DSN},
			BaseURL: "http://localhost",
			MFA:     &MFAConfig{EncryptionKey: testHexKey},
		})
		require.NoError(t, err)
		assert.NotContains(t, logs.String(), "still enrolled")
	})
}

// Test_Integration_ConstructionSurvivesPendingMigration is the case that would otherwise
// bite a real consumer: upgrading the library before running migration 000006 leaves
// totp_credentials absent, and the enrolment check must not turn that into a startup
// crash loop.
func Test_Integration_ConstructionSurvivesPendingMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	rawDB, ctr, err := CreateTestPostgres(t.Context())
	require.NoError(t, err)
	CleanupIntegration(t, ctr, rawDB)

	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)

	// Deliberately no migrations: not one of the library's tables exists.
	logs := captureLogs(t, slog.LevelWarn)

	ac, err := NewAuthClient(&AuthConfig{
		Db:      &DatabaseConfig{Dsn: dsn},
		BaseURL: "http://localhost",
	})
	require.NoError(t, err, "a pending migration must not stop the client from being built")
	assert.False(t, ac.CanUseMFA())
	assert.NotContains(t, logs.String(), "still enrolled",
		"a missing table is not evidence of a downgrade")
}
