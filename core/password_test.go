package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- policy resolution -----------------------------------------------------

func TestResolvePasswordPolicy(t *testing.T) {
	t.Run("nil config preserves the historical rule and leaves the breach check off", func(t *testing.T) {
		p := resolvePasswordPolicy(nil)
		assert.Equal(t, DefaultPasswordMinLength, p.minRunes)
		assert.Equal(t, MaxPasswordBytes, p.maxBytes)
		assert.Zero(t, p.minCharClasses, "no class requirement by default")
		assert.False(t, p.rejectEmailSimilarity, "opt-in, so an upgrade changes nothing")
		assert.Equal(t, BreachCheckOff, p.breach.mode)
	})

	t.Run("clamps MaxLength to the bcrypt byte limit", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{MaxLength: 200})
		assert.Equal(t, MaxPasswordBytes, p.maxBytes,
			"accepting more would silently truncate and give false confidence")
	})

	t.Run("honours a stricter configured policy", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{MinLength: 14, MaxLength: 40, MinCharClasses: 3})
		assert.Equal(t, 14, p.minRunes)
		assert.Equal(t, 40, p.maxBytes)
		assert.Equal(t, 3, p.minCharClasses)
	})

	t.Run("defaults the breach threshold and timeout when a mode is set", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{
			BreachCheck: &BreachCheckConfig{Mode: BreachCheckBlock},
		})
		assert.Equal(t, DefaultBreachThreshold, p.breach.threshold)
		assert.Equal(t, DefaultBreachTimeout, p.breach.timeout)
		assert.NotNil(t, p.breach.checker, "block mode without a checker should get the bundled one")
	})
}

// --- validation ------------------------------------------------------------

func TestPasswordPolicy_Validate(t *testing.T) {
	const email = "alice@example.com"

	t.Run("accepts a password meeting the default policy", func(t *testing.T) {
		assert.NoError(t, resolvePasswordPolicy(nil).validate("correct horse battery", email))
	})

	t.Run("rejects a password shorter than the minimum", func(t *testing.T) {
		err := resolvePasswordPolicy(nil).validate("short", email)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "8")
	})

	t.Run("counts the minimum in characters, not bytes", func(t *testing.T) {
		// Eight characters, but 24 bytes: a byte-based minimum would accept a shorter
		// passphrase than intended, and a user counting characters would be confused.
		assert.NoError(t, resolvePasswordPolicy(nil).validate("日本語のパスワード", email))
	})

	t.Run("rejects a password over the bcrypt byte limit", func(t *testing.T) {
		err := resolvePasswordPolicy(nil).validate(strings.Repeat("a", MaxPasswordBytes+1), email)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "72")
	})

	t.Run("measures the maximum in bytes, so multi-byte passphrases can exceed it", func(t *testing.T) {
		// 25 characters but 75 bytes — bcrypt would truncate it, so it must be rejected.
		err := resolvePasswordPolicy(nil).validate(strings.Repeat("パ", 25), email)
		require.Error(t, err)
	})

	t.Run("requires the configured number of character classes", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{MinCharClasses: 3})
		require.Error(t, p.validate("alllowercaseletters", email))
		assert.NoError(t, p.validate("Lowercase1Upper", email))
	})

	t.Run("rejects a blocklisted password regardless of case", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{Blocklist: []string{"CompanyName123"}})
		require.Error(t, p.validate("companyname123", email))
	})

	t.Run("rejects a password built from the email address when enabled", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{RejectEmailSimilarity: true})
		require.Error(t, p.validate("alice@example.com", email), "the address itself")
		require.Error(t, p.validate("alice12345", email), "the local part with padding")
		assert.NoError(t, p.validate("unrelated passphrase", email))
	})

	t.Run("allows an email-derived password when the rule is off", func(t *testing.T) {
		assert.NoError(t, resolvePasswordPolicy(nil).validate("alice12345", email))
	})

	t.Run("reports every unmet requirement at once", func(t *testing.T) {
		p := resolvePasswordPolicy(&PasswordConfig{
			MinLength:             12,
			MinCharClasses:        3,
			RejectEmailSimilarity: true,
		})
		err := p.validate("alice", email)
		require.Error(t, err)

		msg := err.Error()
		assert.Contains(t, msg, "12", "the length rule")
		assert.Contains(t, msg, "3", "the character-class rule")
		assert.Contains(t, msg, "email", "the similarity rule")
	})
}

// --- breach check ----------------------------------------------------------

// stubChecker stands in for a breach corpus, so no test reaches the network.
type stubChecker struct {
	count int
	err   error
	calls int
}

func (s *stubChecker) TimesBreached(context.Context, string) (int, error) {
	s.calls++
	return s.count, s.err
}

func breachPolicy(t *testing.T, mode BreachCheckMode, c *stubChecker, threshold int) passwordPolicy {
	t.Helper()
	return resolvePasswordPolicy(&PasswordConfig{
		BreachCheck: &BreachCheckConfig{Mode: mode, Checker: c, Threshold: threshold},
	})
}

func TestAuthClient_CheckBreached(t *testing.T) {
	ctx := context.Background()

	t.Run("off mode never consults the checker", func(t *testing.T) {
		c := &stubChecker{count: 9999}
		ac := &AuthClient{password: breachPolicy(t, BreachCheckOff, c, 1)}
		assert.NoError(t, ac.checkBreached(ctx, "hunter2"))
		assert.Zero(t, c.calls, "an outbound call must not happen when the check is off")
	})

	t.Run("block mode rejects a breached password", func(t *testing.T) {
		c := &stubChecker{count: 4000}
		ac := &AuthClient{password: breachPolicy(t, BreachCheckBlock, c, 1)}
		err := ac.checkBreached(ctx, "hunter2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "breach")
	})

	t.Run("block mode accepts a password below the threshold", func(t *testing.T) {
		c := &stubChecker{count: 2}
		ac := &AuthClient{password: breachPolicy(t, BreachCheckBlock, c, 5)}
		assert.NoError(t, ac.checkBreached(ctx, "hunter2"))
		assert.Equal(t, 1, c.calls)
	})

	t.Run("report mode consults the checker but accepts", func(t *testing.T) {
		c := &stubChecker{count: 4000}
		ac := &AuthClient{password: breachPolicy(t, BreachCheckReport, c, 1)}
		assert.NoError(t, ac.checkBreached(ctx, "hunter2"))
		assert.Equal(t, 1, c.calls, "report mode still measures exposure")
	})

	t.Run("fails open when the checker errors", func(t *testing.T) {
		c := &stubChecker{err: errors.New("corpus unreachable")}
		ac := &AuthClient{password: breachPolicy(t, BreachCheckBlock, c, 1)}
		assert.NoError(t, ac.checkBreached(ctx, "hunter2"),
			"a third-party outage must not become a sign-up outage")
	})

	t.Run("fails open when the checker exceeds the timeout", func(t *testing.T) {
		slow := &blockingChecker{released: make(chan struct{})}
		defer close(slow.released)

		p := resolvePasswordPolicy(&PasswordConfig{
			BreachCheck: &BreachCheckConfig{Mode: BreachCheckBlock, Checker: slow, Timeout: 20 * time.Millisecond},
		})
		ac := &AuthClient{password: p}
		assert.NoError(t, ac.checkBreached(ctx, "hunter2"))
	})
}

// blockingChecker honours its context deadline, so the timeout path is exercised without
// a sleep in the test body.
type blockingChecker struct{ released chan struct{} }

func (b *blockingChecker) TimesBreached(ctx context.Context, _ string) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-b.released:
		return 0, nil
	}
}
