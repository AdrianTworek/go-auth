package core

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultPasswordMinLength is the fallback minimum password length, in characters.
	DefaultPasswordMinLength = 8
	// MaxPasswordBytes is a hard ceiling on password length, in bytes, applied whatever
	// the configuration says: bcrypt silently ignores anything beyond 72 bytes, so
	// accepting a longer password would give the user a false sense of strength.
	MaxPasswordBytes = 72
	// DefaultBreachThreshold is how many sightings make a password count as breached.
	DefaultBreachThreshold = 1
	// DefaultBreachTimeout bounds a breached-password lookup.
	DefaultBreachTimeout = 2 * time.Second
	// minEmailLocalMatch is the shortest email local part worth matching against a
	// password. Below it, the rule would reject far too much: a two-letter fragment
	// appears in innumerable good passphrases.
	minEmailLocalMatch = 3
)

// BreachCheckMode selects what happens when a candidate password is found in a breach
// corpus.
type BreachCheckMode int

const (
	// BreachCheckOff never consults the checker. It is the default: a library must not
	// start contacting a third party because someone upgraded it.
	BreachCheckOff BreachCheckMode = iota
	// BreachCheckReport consults the checker and logs what it finds but still accepts the
	// password. Use it to measure exposure across an existing user base before rejecting
	// anyone.
	BreachCheckReport
	// BreachCheckBlock rejects a password seen at least Threshold times.
	BreachCheckBlock
)

// BreachChecker reports how many times a password appears in known breach corpora.
// Implement it to consult a local copy and make no outbound calls at all;
// NewHIBPBreachChecker is the bundled implementation.
type BreachChecker interface {
	// TimesBreached returns the number of sightings, or an error. Callers treat an error
	// as "unknown" and allow the password, so an implementation should not invent a zero.
	TimesBreached(ctx context.Context, password string) (int, error)
}

// PasswordConfig describes what counts as an acceptable password. It is enforced
// identically everywhere a password is set — registration, password-reset completion and
// change-password — so a user cannot route around it by picking a different flow.
//
// A nil PasswordConfig keeps the library's historical rule (8 to 72, no breach check),
// so upgrading changes nothing.
type PasswordConfig struct {
	// MinLength is the minimum length in characters (not bytes, so a multi-byte
	// passphrase isn't penalised for its encoding).
	//
	// Default: 8
	MinLength int
	// MaxLength is the maximum length in bytes, capped at MaxPasswordBytes however it is
	// set, because bcrypt ignores the remainder.
	//
	// Default: 72
	MaxLength int
	// MinCharClasses is how many of uppercase, lowercase, digits and symbols must appear
	// (0 to 4). One count is used rather than four independent flags: it expresses the
	// same intent without a configuration surface where four toggles interact.
	//
	// Default: 0 (no class requirement)
	MinCharClasses int
	// Blocklist is a set of passwords to refuse outright, matched case-insensitively.
	// Use it for strings specific to your product or brand.
	//
	// Default: nil
	Blocklist []string
	// RejectEmailSimilarity refuses passwords built from the user's own address — the
	// first thing a targeted attacker tries. Off by default so that a nil config and an
	// upgrade both leave behaviour unchanged.
	//
	// Default: false
	RejectEmailSimilarity bool
	// BreachCheck opts into checking candidate passwords against a breach corpus.
	//
	// Default: nil (off)
	BreachCheck *BreachCheckConfig
}

// BreachCheckConfig tunes the breached-password check. It is off unless Mode says
// otherwise, and it fails open: if the corpus is unreachable or slow, the password is
// allowed and the failure logged, because a third-party outage must not take a sign-up
// flow down with it.
type BreachCheckConfig struct {
	// Mode selects off / report-only / block.
	//
	// Default: BreachCheckOff
	Mode BreachCheckMode
	// Threshold is the number of sightings at which a password is rejected in
	// BreachCheckBlock mode.
	//
	// Default: 1
	Threshold int
	// Timeout bounds one lookup.
	//
	// Default: 2s
	Timeout time.Duration
	// Checker overrides the bundled Have I Been Pwned implementation — with an offline
	// corpus, say. When nil and Mode is not off, the bundled one is used.
	//
	// Default: nil
	Checker BreachChecker
}

// passwordPolicy is PasswordConfig with every default applied, so validation never reads
// raw config. Lengths are split by unit deliberately: minRunes is what a user counts,
// maxBytes is what bcrypt counts.
type passwordPolicy struct {
	minRunes              int
	maxBytes              int
	minCharClasses        int
	blocklist             map[string]struct{}
	rejectEmailSimilarity bool
	breach                resolvedBreachCheck
}

type resolvedBreachCheck struct {
	mode      BreachCheckMode
	threshold int
	timeout   time.Duration
	checker   BreachChecker
}

func resolvePasswordPolicy(c *PasswordConfig) passwordPolicy {
	p := passwordPolicy{
		minRunes: DefaultPasswordMinLength,
		maxBytes: MaxPasswordBytes,
		breach:   resolveBreachCheck(nil),
	}
	if c == nil {
		return p
	}

	if c.MinLength > 0 {
		p.minRunes = c.MinLength
	}
	// A configured maximum can only tighten the bcrypt ceiling, never raise it.
	if c.MaxLength > 0 && c.MaxLength < MaxPasswordBytes {
		p.maxBytes = c.MaxLength
	}
	if c.MinCharClasses > 0 {
		p.minCharClasses = c.MinCharClasses
	}
	p.rejectEmailSimilarity = c.RejectEmailSimilarity

	if len(c.Blocklist) > 0 {
		p.blocklist = make(map[string]struct{}, len(c.Blocklist))
		for _, blocked := range c.Blocklist {
			p.blocklist[strings.ToLower(strings.TrimSpace(blocked))] = struct{}{}
		}
	}

	p.breach = resolveBreachCheck(c.BreachCheck)
	return p
}

func resolveBreachCheck(c *BreachCheckConfig) resolvedBreachCheck {
	b := resolvedBreachCheck{
		mode:      BreachCheckOff,
		threshold: DefaultBreachThreshold,
		timeout:   DefaultBreachTimeout,
	}
	if c == nil {
		return b
	}

	b.mode = c.Mode
	if c.Threshold > 0 {
		b.threshold = c.Threshold
	}
	if c.Timeout > 0 {
		b.timeout = c.Timeout
	}
	b.checker = c.Checker
	if b.mode != BreachCheckOff && b.checker == nil {
		b.checker = NewHIBPBreachChecker(b.timeout)
	}
	return b
}

// validate reports every way the password fails the policy in a single error, rather than
// the first: a sign-up form can then show the whole picture instead of rejecting the user
// once per rule.
func (p passwordPolicy) validate(password, email string) error {
	var unmet []string

	if utf8.RuneCountInString(password) < p.minRunes {
		unmet = append(unmet, fmt.Sprintf("be at least %d characters long", p.minRunes))
	}
	if len(password) > p.maxBytes {
		unmet = append(unmet, fmt.Sprintf("be at most %d bytes long", p.maxBytes))
	}
	if p.minCharClasses > 0 && countCharClasses(password) < p.minCharClasses {
		unmet = append(unmet, fmt.Sprintf(
			"use at least %d of uppercase letters, lowercase letters, digits and symbols",
			p.minCharClasses,
		))
	}
	if _, blocked := p.blocklist[strings.ToLower(password)]; blocked {
		unmet = append(unmet, "not be a disallowed password")
	}
	if p.rejectEmailSimilarity && resemblesEmail(password, email) {
		unmet = append(unmet, "not be based on your email address")
	}

	if len(unmet) == 0 {
		return nil
	}
	return fmt.Errorf("password must %s", joinRequirements(unmet))
}

func countCharClasses(s string) int {
	var upper, lower, digit, symbol bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}

	classes := 0
	for _, present := range []bool{upper, lower, digit, symbol} {
		if present {
			classes++
		}
	}
	return classes
}

// resemblesEmail reports whether the password is built from the user's own address: the
// whole address, or the local part appearing anywhere in it, ignoring case.
func resemblesEmail(password, email string) bool {
	if email == "" {
		return false
	}

	pw := strings.ToLower(password)
	addr := strings.ToLower(strings.TrimSpace(email))
	if strings.Contains(pw, addr) {
		return true
	}

	local, _, ok := strings.Cut(addr, "@")
	if !ok || len(local) < minEmailLocalMatch {
		return false
	}
	return strings.Contains(pw, local)
}

// joinRequirements renders the unmet requirements as one readable clause.
func joinRequirements(items []string) string {
	switch len(items) {
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

// checkPassword applies the configured policy and, when enabled, the breached-password
// check, returning an error suitable for showing the user.
//
// Call it after the endpoint's abuse throttling and before bcrypt: throttling first,
// because otherwise an unauthenticated caller could drive unbounded outbound lookups from
// the server; before bcrypt, so a rejected password never pays the hashing cost.
func (ac *AuthClient) checkPassword(ctx context.Context, password, email string) error {
	if err := ac.password.validate(password, email); err != nil {
		return err
	}
	return ac.checkBreached(ctx, password)
}

// checkBreached consults the configured breach corpus. It fails open on any error or
// timeout — logging loudly — for the same reason the rate limiter does: an availability
// dependency on a third party is unacceptable in a sign-up flow.
func (ac *AuthClient) checkBreached(ctx context.Context, password string) error {
	b := ac.password.breach
	if b.mode == BreachCheckOff || b.checker == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	timesSeen, err := b.checker.TimesBreached(ctx, password)
	if err != nil {
		slog.Error("breached-password check failed, allowing the password", "error", err)
		return nil
	}
	if timesSeen < b.threshold {
		return nil
	}

	if b.mode == BreachCheckReport {
		slog.Warn("password found in a breach corpus, allowing it (report-only mode)",
			"timesSeen", timesSeen)
		return nil
	}
	return fmt.Errorf(
		"this password has appeared in known data breaches %d times, so please choose a different one",
		timesSeen,
	)
}
