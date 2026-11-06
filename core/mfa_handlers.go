package core

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/jmoiron/sqlx"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// reauthRequest is the body shared by the three management endpoints that require
// re-authentication. Password is deliberately not `required`: see reauthenticate.
type reauthRequest struct {
	Password string `json:"password"`
}

// readReauthRequest decodes a re-authentication body, tolerating a completely empty one.
//
// A passwordless account has nothing to send, and requiring it to post `{}` to disable
// its own second factor would be a pointless papercut. Malformed JSON is still rejected.
func readReauthRequest(w http.ResponseWriter, r *http.Request, req *reauthRequest) error {
	if err := readAndValidateJSON(w, r, req); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// reauthenticate checks the caller's password before a change to their security
// settings, so that someone who finds an unlocked laptop cannot switch off the
// protection the second factor exists to provide.
//
// An account with no password — OAuth-only, or magic-link-only — is authorised by its
// session alone. ChangePasswordHandler's answer in that situation is to redirect the
// user to the reset flow, which would be wrong here: it would mean the users who most
// want a second factor could never enrol one. The precedent followed instead is
// ChangeEmailHandler, which already reasons this way about accounts that hold no
// password.
func (ac *AuthClient) reauthenticate(w http.ResponseWriter, user *store.User, password string) bool {
	if len(user.Password) == 0 {
		return true
	}
	if !user.Password.Compare(password) {
		writeJSONError(w, http.StatusBadRequest, "Current password is incorrect")
		return false
	}
	return true
}

// requireMFAEnabled guards the handlers against being reached when the capability is not
// configured. The adapters do not mount these routes in that case, so this is depth
// rather than the primary control — it makes each handler honest on its own, for a
// consumer who wires them by hand.
func (ac *AuthClient) requireMFAEnabled(w http.ResponseWriter) bool {
	if !ac.mfa.enabled {
		writeJSONError(w, http.StatusNotFound, "Two-factor authentication is not enabled")
		return false
	}
	return true
}

// requireConfirmedTOTP reports whether the caller has an active second factor,
// answering ErrNotFound when they do not. An enrolment that was started but never
// confirmed counts as none: it is inert.
//
// It deliberately returns only an error. Nothing in this slice needs the credential
// itself — the verify handler does, and reads it directly.
func (ac *AuthClient) requireConfirmedTOTP(ctx context.Context, userID string) error {
	cred, err := ac.store.TOTP.GetForUser(ctx, nil, userID)
	if err != nil {
		return err
	}
	if !cred.Confirmed() {
		return store.ErrNotFound
	}
	return nil
}

// issueBackupCodes replaces a user's recovery codes with a fresh set, returning the
// plaintext codes for the one response that is allowed to contain them.
//
// The previous set is deleted rather than marked superseded, because the guarantee is
// that codes the user believes are retired actually are.
//
// A duplicate inside a generated set would violate the unique index and fail the
// request. At 50 bits per code that is somewhere around a one-in-a-trillion event for a
// set of ten, and failing loudly is the right outcome: silently inserting fewer codes
// than promised would be worse.
func (ac *AuthClient) issueBackupCodes(ctx context.Context, tx *sqlx.Tx, userID string) ([]string, error) {
	codes := make([]string, 0, ac.mfa.backupCodeCount)
	hashes := make([]string, 0, ac.mfa.backupCodeCount)

	for range ac.mfa.backupCodeCount {
		code, err := auth.NewBackupCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, auth.HashToken(auth.NormalizeBackupCode(code)))
	}

	if err := ac.store.BackupCode.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := ac.store.BackupCode.CreateMany(ctx, tx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// auditMFA emits one of the two-factor audit events. Like every audit event it fires
// after the change is committed, so a handler error is logged rather than failing a
// request whose action already happened.
func (ac *AuthClient) auditMFA(
	w http.ResponseWriter,
	r *http.Request,
	eventType AuthEventType,
	user *store.User,
	reason string,
) bool {
	return ac.triggerAudit(r.Context(), ac.newAuditEvent(eventType, w, r, user, AuditInfo{
		TargetType: AuditTargetMFA,
		TargetID:   user.ID,
		Reason:     reason,
	}))
}

// BeginTOTPEnrolmentHandler starts enrolment in an authenticator app. It must be mounted
// behind AuthMiddleware.
//
// Enrolment is two-step and this is the inert half: the secret is stored unconfirmed and
// has no effect on sign-in until TOTPEnrolmentConfirmHandler accepts a generated code.
// Without that, a mis-scanned QR code would lock the user out of their own account at
// the next sign-in, with no way back.
//
// The response carries the base32 secret as well as the otpauth:// URI, so a user on a
// device with no camera can type it in. Rendering the URI as a QR code is the consumer's
// job; the library deliberately does not generate images.
func (ac *AuthClient) BeginTOTPEnrolmentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		var req reauthRequest
		if err := readReauthRequest(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ac.guardSensitive(w, r, "mfa_setup", user.ID) {
			return
		}
		if !ac.reauthenticate(w, user, req.Password) {
			return
		}

		// Re-enrolling on top of a live factor would invalidate the authenticator the
		// user is currently relying on, so it is refused rather than silently replacing
		// it. An *unconfirmed* row is replaced freely — that is a user who mis-scanned
		// and is starting again, which has to keep working.
		existing, err := ac.store.TOTP.GetForUser(r.Context(), nil, user.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			serverError(w, r, err)
			return
		}
		if err == nil && existing.Confirmed() {
			writeJSONError(w, http.StatusConflict,
				"Two-factor authentication is already enabled. Disable it first if you want to set up a new authenticator.")
			return
		}

		secret, err := auth.NewTOTPSecret()
		if err != nil {
			serverError(w, r, err)
			return
		}
		ciphertext, nonce, err := auth.Encrypt(ac.mfa.key, secret)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.TOTP.Upsert(r.Context(), nil, &store.TOTPCredential{
			UserID: user.ID,
			Secret: ciphertext,
			Nonce:  nonce,
		}); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"secret": auth.EncodeTOTPSecret(secret),
			"uri":    auth.OTPAuthURI(ac.mfa.issuer, user.Email, secret, ac.mfa.digits, ac.mfa.period),
		})
	}
}

// TOTPEnrolmentConfirmHandler activates an enrolment once the user proves their
// authenticator is set up correctly. It must be mounted behind AuthMiddleware.
//
// No password is required: the setup call a moment ago already re-authenticated, and the
// generated code is the proof that actually matters here.
//
// The backup codes in this response are returned EXACTLY ONCE and are never retrievable
// again — only their hashes are stored. A consumer that does not show them to the user
// at this point has lost them. They are issued here rather than at setup so that codes
// are never handed out for a factor that never becomes active.
func (ac *AuthClient) TOTPEnrolmentConfirmHandler() http.HandlerFunc {
	type request struct {
		Code string `json:"code" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ac.guardSensitive(w, r, "mfa_confirm", user.ID) {
			return
		}

		cred, err := ac.store.TOTP.GetForUser(r.Context(), nil, user.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusBadRequest,
					"No enrolment is in progress. Start one before confirming.")
				return
			}
			serverError(w, r, err)
			return
		}
		if cred.Confirmed() {
			writeJSONError(w, http.StatusBadRequest, "Two-factor authentication is already enabled")
			return
		}

		secret, err := auth.Decrypt(ac.mfa.key, cred.Secret, cred.Nonce)
		if err != nil {
			serverError(w, r, err)
			return
		}

		step, valid := auth.VerifyTOTP(secret, req.Code, ac.now(), ac.mfa.period, ac.mfa.digits, ac.mfa.skewSteps)
		if !valid {
			// The factor stays inactive, which is the whole point of confirming.
			if !ac.auditMFA(w, r, EventMFAVerificationFailed, user, MFAFailureInvalidCode) {
				return
			}
			writeJSONError(w, http.StatusBadRequest, "That code is not valid. Check your authenticator app and try again.")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		committed := false
		defer ac.rollbackUnless(tx, &committed)()

		if err = ac.store.TOTP.Confirm(r.Context(), tx, user.ID, ac.now().UTC()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusBadRequest, "Two-factor authentication is already enabled")
				return
			}
			serverError(w, r, err)
			return
		}

		// Claim the confirming code's step so it cannot immediately be replayed at
		// sign-in. A failure here means something claimed the step concurrently, which
		// for a code being used to confirm is not a state worth reasoning about.
		if _, err = ac.store.TOTP.ClaimStep(r.Context(), tx, user.ID, step); err != nil {
			serverError(w, r, err)
			return
		}

		codes, err := ac.issueBackupCodes(r.Context(), tx, user.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}
		committed = true

		if !ac.auditMFA(w, r, EventMFAEnabled, user, "") {
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"message":     "Two-factor authentication enabled",
			"backupCodes": codes,
		})
	}
}

// DisableTOTPHandler turns the second factor off. It must be mounted behind
// AuthMiddleware.
//
// The secret and every backup code are deleted rather than flagged inactive: keeping a
// secret for a factor the user has switched off is a liability with no purpose.
func (ac *AuthClient) DisableTOTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		var req reauthRequest
		if err := readReauthRequest(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ac.guardSensitive(w, r, "mfa_disable", user.ID) {
			return
		}
		if !ac.reauthenticate(w, user, req.Password) {
			return
		}

		if err := ac.requireConfirmedTOTP(r.Context(), user.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusBadRequest, "Two-factor authentication is not enabled")
				return
			}
			serverError(w, r, err)
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		committed := false
		defer ac.rollbackUnless(tx, &committed)()

		if err = ac.store.TOTP.DeleteForUser(r.Context(), tx, user.ID); err != nil {
			serverError(w, r, err)
			return
		}
		if err = ac.store.BackupCode.DeleteForUser(r.Context(), tx, user.ID); err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}
		committed = true

		if !ac.auditMFA(w, r, EventMFADisabled, user, "") {
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Two-factor authentication disabled"})
	}
}

// RegenerateBackupCodesHandler issues a fresh set of recovery codes and invalidates the
// previous one. It must be mounted behind AuthMiddleware.
//
// As at confirmation, the plaintext codes are returned exactly once.
func (ac *AuthClient) RegenerateBackupCodesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		var req reauthRequest
		if err := readReauthRequest(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ac.guardSensitive(w, r, "mfa_backup_codes", user.ID) {
			return
		}
		if !ac.reauthenticate(w, user, req.Password) {
			return
		}

		// Codes without a factor are meaningless, so there is nothing to regenerate.
		if err := ac.requireConfirmedTOTP(r.Context(), user.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusBadRequest, "Two-factor authentication is not enabled")
				return
			}
			serverError(w, r, err)
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		committed := false
		defer ac.rollbackUnless(tx, &committed)()

		codes, err := ac.issueBackupCodes(r.Context(), tx, user.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}
		committed = true

		if !ac.auditMFA(w, r, EventMFABackupCodesRegenerated, user, "") {
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"message":     "Backup codes regenerated",
			"backupCodes": codes,
		})
	}
}

// MFAStatusHandler reports whether the caller has a second factor active and how many
// backup codes they have left. It must be mounted behind AuthMiddleware.
//
// No re-authentication and no throttle: it is a read of the caller's own state, like
// GET /auth/sessions.
func (ac *AuthClient) MFAStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.requireMFAEnabled(w) {
			return
		}
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// enabled reflects a *confirmed* enrolment only. Reporting an enrolment in
		// progress as enabled would be a lie a UI would act on.
		enabled := true
		if err := ac.requireConfirmedTOTP(r.Context(), user.ID); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				serverError(w, r, err)
				return
			}
			enabled = false
		}

		remaining := 0
		if enabled {
			var err error
			if remaining, err = ac.store.BackupCode.CountUnused(r.Context(), nil, user.ID); err != nil {
				serverError(w, r, err)
				return
			}
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"enabled":              enabled,
			"backupCodesRemaining": remaining,
		})
	}
}
