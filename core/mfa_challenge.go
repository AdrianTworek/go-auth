package core

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/jmoiron/sqlx"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// genericMFAFailureMessage is returned for every rejected verification — wrong code,
// replayed code, wrong backup code, unknown or expired challenge. The reasons are
// distinguished for the consumer's own records via EventMFAVerificationFailed, not for
// the caller.
const genericMFAFailureMessage = "That code is not valid. Check your authenticator app and try again."

// secondFactorRequired reports whether a user must satisfy a second factor before a
// session may be issued.
//
// Both opt-ins have to be true: the consumer configured the capability, and this user
// confirmed an enrolment. An enrolment that was started and never confirmed is inert.
func (ac *AuthClient) secondFactorRequired(ctx context.Context, tx *sqlx.Tx, userID string) (bool, error) {
	if !ac.mfa.enabled {
		return false, nil
	}

	cred, err := ac.store.TOTP.GetForUser(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return cred.Confirmed(), nil
}

// issueChallenge mints the short-lived, single-use token that stands in for the session
// a correct credential would otherwise have produced.
//
// It is a verifications row rather than a "pending" session, deliberately. A session
// marked pending would put a partly-authenticated row in the sessions table, and then
// every authenticated path would have to remember to check the flag — one forgotten
// check is a complete bypass, and nothing in the type system would catch it. With a
// challenge there is simply no session to misuse.
func (ac *AuthClient) issueChallenge(ctx context.Context, tx *sqlx.Tx, userID string) (string, error) {
	return ac.store.Verification.Create(
		ctx, tx,
		ac.newVerification(auth.TwoFactorChallengeIntent, nil, auth.NewNullString(userID)),
	)
}

// challengeIssuedHook fires EventMFAChallengeIssued and reports whether the caller
// should still write its own response, in the manner of fireRateLimitHook. A hook that
// redirects has already written one.
func (ac *AuthClient) challengeIssuedHook(
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	challenge, flow string,
) bool {
	event := NewAuthEvent(EventMFAChallengeIssued, w, r, user)
	event.MFA = &MFAChallengeInfo{Challenge: challenge, Flow: flow}

	cont, err := ac.hookStore.Trigger(r.Context(), event)
	if err != nil {
		serverError(w, r, err)
		return false
	}
	return cont
}

// writeChallengeResponse answers an API-shaped sign-in with the challenge instead of a
// session. Note what is absent: no Set-Cookie. That is the security property, not the
// body.
func writeChallengeResponse(w http.ResponseWriter, challenge string) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"mfaRequired": true,
		"challenge":   challenge,
	})
}

// magicLinkMFARedirect sends a challenged magic-link sign-in to the page configured for
// it, carrying the challenge as a query parameter. Construction refuses a config where
// this would be empty, so the URL is always set by the time this runs.
func (ac *AuthClient) magicLinkMFARedirect(w http.ResponseWriter, r *http.Request, challenge string) {
	target := ac.config.Session.MagicLinkMFARedirectURL

	parsed, err := url.Parse(target)
	if err != nil {
		// Unreachable for a URL that construction accepted, but falling back to the
		// failure page is the safe answer: it withholds the session either way.
		ac.FailedMagicLinkRedirect(w, r)
		return
	}
	query := parsed.Query()
	query.Set("challenge", challenge)
	parsed.RawQuery = query.Encode()

	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// isTOTPShaped decides which factor a submitted code is, by shape: a value of exactly
// the configured digit count, all digits, is a code from an authenticator app.
//
// Backup codes are base32 in two hyphenated groups of five, so the two shapes cannot
// collide. Dispatching on shape rather than trying both in turn keeps one submission
// costing one attempt against the throttle.
func isTOTPShaped(code string, digits int) bool {
	if len(code) != digits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// MFAVerifyHandler exchanges a challenge and a valid code for a session. It is the
// public half of the two-step sign-in and must NOT be mounted behind AuthMiddleware: by
// definition the caller has no session yet.
//
// A failed code deliberately does not consume the challenge, so that one mistyped digit
// does not send the user back to re-enter their password. That is a usability decision
// with a real security cost, and it is defensible only because the attempts are bounded
// by RateLimitConfig.MFAVerify. If that limit is ever loosened or removed, this decision
// has to be revisited with it.
func (ac *AuthClient) MFAVerifyHandler() http.HandlerFunc {
	type request struct {
		Challenge string `json:"challenge" validate:"required"`
		Code      string `json:"code" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}

		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Per-IP first: it needs no knowledge of the account, so it runs before any
		// database work.
		if !ac.guardMFAVerifyIP(w, r) {
			return
		}

		// Peek rather than consume: a wrong code must leave the challenge usable.
		challenge, err := ac.store.Verification.GetByToken(r.Context(), nil, req.Challenge, auth.TwoFactorChallengeIntent)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				serverError(w, r, err)
				return
			}
			// Unknown or expired. There is no user to attribute this to, so the event
			// carries no target — it is still worth emitting, because a burst of these
			// is what guessing at challenges looks like.
			if !ac.auditMFAFailure(w, r, nil, "", MFAFailureInvalidChallenge) {
				return
			}
			writeJSONError(w, http.StatusUnauthorized, genericMFAFailureMessage)
			return
		}
		if !challenge.UserID.Valid {
			writeJSONError(w, http.StatusUnauthorized, genericMFAFailureMessage)
			return
		}
		userID := challenge.UserID.String

		if !ac.guardMFAVerifyAccount(w, r, userID) {
			return
		}

		user, err := ac.store.User.GetByID(r.Context(), nil, userID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusUnauthorized, genericMFAFailureMessage)
				return
			}
			serverError(w, r, err)
			return
		}

		cred, err := ac.store.TOTP.GetForUser(r.Context(), nil, userID)
		if err != nil || !cred.Confirmed() {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				serverError(w, r, err)
				return
			}
			// The factor was disabled between the challenge being issued and this
			// request. The challenge is tied to a factor that no longer exists, so it
			// cannot be satisfied — do not fall through to issuing a session.
			if !ac.auditMFAFailure(w, r, user, userID, MFAFailureInvalidChallenge) {
				return
			}
			writeJSONError(w, http.StatusUnauthorized, genericMFAFailureMessage)
			return
		}

		submitted := auth.NormalizeBackupCode(req.Code)
		usedBackupCode := !isTOTPShaped(submitted, ac.mfa.digits)

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		committed := false
		defer ac.rollbackUnless(tx, &committed)()

		// Spend the factor inside the transaction, so a later failure leaves the code
		// unspent rather than burning it without issuing a session.
		if usedBackupCode {
			if _, err = ac.store.BackupCode.Consume(r.Context(), tx, userID, auth.HashToken(submitted)); err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					serverError(w, r, err)
					return
				}
				if !ac.failVerification(w, r, user, userID, MFAFailureInvalidBackupCode) {
					return
				}
				return
			}
		} else {
			secret, decErr := auth.Decrypt(ac.mfa.key, cred.Secret, cred.Nonce)
			if decErr != nil {
				serverError(w, r, decErr)
				return
			}

			step, valid := auth.VerifyTOTP(secret, submitted, ac.now(), ac.mfa.period, ac.mfa.digits, ac.mfa.skewSteps)
			if !valid {
				if !ac.failVerification(w, r, user, userID, MFAFailureInvalidCode) {
					return
				}
				return
			}

			// Arithmetically correct is not the same as unspent. A code stays valid for
			// its whole window plus the configured skew, so one observed in transit
			// could otherwise be replayed inside its remaining validity.
			claimed, claimErr := ac.store.TOTP.ClaimStep(r.Context(), tx, userID, step)
			if claimErr != nil {
				serverError(w, r, claimErr)
				return
			}
			if !claimed {
				if !ac.failVerification(w, r, user, userID, MFAFailureReplayedCode) {
					return
				}
				return
			}
		}

		// Only now is the challenge spent. Consume is atomic, so two requests racing on
		// the same challenge resolve to exactly one session.
		if _, err = ac.store.Verification.Consume(r.Context(), tx, req.Challenge, auth.TwoFactorChallengeIntent); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				serverError(w, r, err)
				return
			}
			if !ac.failVerification(w, r, user, userID, MFAFailureInvalidChallenge) {
				return
			}
			return
		}

		expiresAt := ac.sessionExpiry()
		token, err := ac.store.Session.Create(r.Context(), tx, &store.Session{
			UserID:    user.ID,
			IPAddress: ac.clientIP(r),
			UserAgent: r.UserAgent(),
			ExpiresAt: expiresAt,
		})
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}
		committed = true

		http.SetCookie(w, ac.newSessionCookie(token, expiresAt))

		// Both factors passed, so earlier fumbled codes should not leave the user
		// throttled.
		ac.resetMFAVerifyLimit(r.Context(), userID)

		if !ac.auditMFA(w, r, EventMFAVerified, user, "") {
			return
		}
		if usedBackupCode && !ac.auditMFA(w, r, EventMFABackupCodeUsed, user, "") {
			return
		}

		// EventAfterLogin fires here rather than at the first step, because this is the
		// point at which the user is actually signed in.
		cont, err := ac.hookStore.Trigger(r.Context(), NewAuthEvent(EventAfterLogin, w, r, user))
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !cont {
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}

// failVerification records a rejected attempt and writes the uniform failure response.
// It returns false when a hook has already written one, so callers can `return`
// unconditionally afterwards.
//
// The response is identical for every reason, so the endpoint cannot be used to learn
// whether a code was wrong, already used, or belonged to a challenge that had expired.
func (ac *AuthClient) failVerification(
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	userID, reason string,
) bool {
	if !ac.auditMFAFailure(w, r, user, userID, reason) {
		return false
	}
	writeJSONError(w, http.StatusUnauthorized, genericMFAFailureMessage)
	return true
}

// auditMFAFailure emits EventMFAVerificationFailed. Unlike the other two-factor audit
// events it describes something that did not happen, so there is nothing committed and
// user may be nil when the challenge named nobody.
func (ac *AuthClient) auditMFAFailure(
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	userID, reason string,
) bool {
	return ac.triggerAudit(r.Context(), ac.newAuditEvent(EventMFAVerificationFailed, w, r, user, AuditInfo{
		TargetType: AuditTargetMFA,
		TargetID:   userID,
		Reason:     reason,
	}))
}
