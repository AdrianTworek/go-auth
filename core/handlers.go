package core

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// genericResetMessage is returned by the send-reset endpoint whether or
// not the email is registered, so the response never reveals account existence.
const genericResetMessage = "If an account with that email exists, a password reset link has been sent."

// genericVerificationMessage is returned by the resend-verification endpoint for
// every outcome, so the response never reveals whether the email is registered or
// whether it is already verified.
const genericVerificationMessage = "If an account with that email exists and is unverified, a verification link has been sent."

func (ac *AuthClient) RegisterHandler() http.HandlerFunc {
	type registerRequest struct {
		Email           string `json:"email" validate:"required,min=3,max=255,email"`
		Password        string `json:"password" validate:"required,min=8,max=72"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=72,eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		newUser := store.NewUser(req.Email, false, nil, nil, nil, nil)
		if err := newUser.Password.Set(req.Password); err != nil {
			serverError(w, r, err)
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventBeforeRegistration,
				w,
				r,
				newUser,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if !cont {
			return
		}

		err = ac.store.User.Create(r.Context(), tx, newUser)
		if err != nil && !errors.Is(err, store.ErrDuplicateEmail) {
			serverError(w, r, err)
			return
		}

		if err != nil && errors.Is(err, store.ErrDuplicateEmail) {
			writeJSONError(w, http.StatusBadRequest, "An account with this email already exists")
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), tx, req.Email)
		if err != nil {
			serverError(w, r, err)
			return
		}

		// Suppress auto-login when verification is required: the new user is unverified.
		var token string
		var sessionExpiresAt time.Time
		if ac.config.Session.LoginAfterRegister && !ac.config.Session.RequireVerifiedEmail {
			sessionExpiresAt = ac.sessionExpiry()
			token, err = ac.store.Session.Create(
				r.Context(),
				tx,
				&store.Session{
					UserID:    user.ID,
					IPAddress: r.RemoteAddr,
					UserAgent: r.UserAgent(),
					ExpiresAt: sessionExpiresAt,
				},
			)
			if err != nil {
				serverError(w, r, err)
				return
			}
		}

		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			tx,
			ac.newVerification(
				auth.EmailVerificationIntent,
				nil,
				auth.NewNullString(user.ID),
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			serverError(w, r, err)
			return
		}

		// The account is already committed at this point, so a failed verification
		// email is non-fatal: log it and let the user re-request verification.
		if err = ac.config.Mailer.SendVerificationEmail(user.Email, verificationToken); err != nil {
			slog.Error("failed to send verification email", "error", err)
		}

		if token != "" && ac.config.Session.LoginAfterRegister {
			cookie := ac.newSessionCookie(token, sessionExpiresAt)
			http.SetCookie(w, cookie)
		}

		cont, err = ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventAfterRegistration,
				w,
				r,
				user,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if !cont {
			return
		}

		writeJSONResponse(w, http.StatusCreated, map[string]any{"message": "User registered successfully"})
	}
}

func (ac *AuthClient) LoginHandler() http.HandlerFunc {
	type loginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		sessCookie, err := r.Cookie(ac.cookieName())
		if err == nil {
			_, err := ac.store.Session.Validate(r.Context(), nil, sessCookie.Value)
			if err == nil {
				writeJSONError(w, http.StatusBadRequest, "User already logged in")
				return
			}
		}

		var req loginRequest
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventBeforeLogin,
				w,
				r,
				nil,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if !cont {
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), nil, req.Email)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				serverError(w, r, err)
				return
			}
			// User not found: spend comparable time on a throwaway bcrypt compare so
			// the response time matches the wrong-password path (anti-enumeration).
			auth.DummyCompare(req.Password)
			writeJSONError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		if !user.Password.Compare(req.Password) {
			writeJSONError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		if ac.config.Session.RequireVerifiedEmail && !user.EmailVerified {
			writeJSONError(w, http.StatusForbidden, "You need to verify your email before logging in. Please check your email for a verification link.")
			return
		}

		sessionExpiresAt := ac.sessionExpiry()
		token, err := ac.store.Session.Create(
			r.Context(),
			nil,
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: sessionExpiresAt,
			},
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		cookie := ac.newSessionCookie(token, sessionExpiresAt)
		http.SetCookie(w, cookie)

		cont, err = ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventAfterLogin,
				w,
				r,
				user,
			),
		)
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

func (ac *AuthClient) GetMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]*store.User{"user": user})
	}
}

func (ac *AuthClient) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// User and the effective session token are populated by AuthMiddleware,
		// which this handler is always mounted behind.
		user, ok := getUserFromContext(r)
		token, tokenOK := getSessionTokenFromContext(r)
		if !ok || !tokenOK {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventLogout,
				w,
				r,
				user,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if !cont {
			return
		}

		if err = ac.store.Session.Delete(r.Context(), nil, token); err != nil {
			serverError(w, r, err)
			return
		}

		cookie := ac.deleteSessionCookie()
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged out successfully"})
	}
}

func (ac *AuthClient) VerifyEmailHandler(extractor ParamExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// On failure we don't write the response immediately. Instead we record the
		// default JSON error and let the deferred block give an
		// EventEmailVerificationFailed hook the first chance to respond (e.g. redirect
		// to a "verification failed" page). Writing eagerly here would race the hook's
		// write: some adapters buffer the response and honor the later redirect, others
		// commit the JSON first, so behaviour differed across frameworks. Deferring the
		// write keeps every adapter consistent.
		verificationFailed := false
		failStatus, failMessage := 0, ""
		fail := func(status int, message string) {
			verificationFailed = true
			failStatus, failMessage = status, message
		}
		failServer := func(err error) {
			slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
			fail(http.StatusInternalServerError, "Internal Server Error")
		}

		defer func() {
			if !verificationFailed {
				return
			}
			cont, err := ac.hookStore.Trigger(
				r.Context(),
				NewAuthEvent(EventEmailVerificationFailed, w, r, nil),
			)
			if err != nil {
				slog.Error("email verification failed hook resulted in error", "error", err.Error())
			}
			// Fall back to the default JSON error only when no hook handled the
			// response (no hook registered, or one returned a plain error).
			if cont || err != nil {
				writeJSONError(w, failStatus, failMessage)
			}
		}()

		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			fail(http.StatusBadRequest, "Token is required")
			return
		}

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventEmailVerificationCallback,
				w,
				r,
				nil,
			),
		)
		if err != nil {
			failServer(err)
			return
		}
		if !cont {
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			failServer(err)
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		// Atomically validate and consume the token; a rollback below restores it.
		token, err := ac.store.Verification.Consume(r.Context(), tx, tokenStr, auth.EmailVerificationIntent)
		if err != nil {
			fail(http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			fail(http.StatusInternalServerError, "Invalid token")
			return
		}

		user, err := ac.store.User.GetByID(r.Context(), tx, token.UserID.String)
		if err != nil {
			failServer(err)
			return
		}

		user.EmailVerified = true
		_, err = ac.store.User.Update(r.Context(), tx, user)
		if err != nil {
			failServer(err)
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			failServer(err)
			return
		}

		cont, err = ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(
				EventEmailVerificationSuccess,
				w,
				r,
				user,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !cont {
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Email verified successfully"})
	}
}

// ResendVerificationHandler re-issues an email-verification link for an account that
// registered but never verified (e.g. the original token expired). It is the recovery
// path for the otherwise dead-ended unverified user. Every outcome returns the same
// generic 200 so the endpoint can't be used to enumerate accounts or learn which
// addresses are already verified.
func (ac *AuthClient) ResendVerificationHandler() http.HandlerFunc {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// respond is used for every non-error outcome so registered, unregistered and
		// already-verified addresses are indistinguishable from the response.
		respond := func() {
			writeJSONResponse(w, http.StatusOK, map[string]any{"message": genericVerificationMessage})
		}

		user, err := ac.store.User.GetByEmail(r.Context(), nil, req.Email)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				respond()
				return
			}
			serverError(w, r, err)
			return
		}

		// Nothing to do for an already-verified account, but don't reveal that.
		if user.EmailVerified {
			respond()
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			tx,
			ac.newVerification(
				auth.EmailVerificationIntent,
				nil,
				auth.NewNullString(user.ID),
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.config.Mailer.SendVerificationEmail(user.Email, verificationToken); err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}

		respond()
	}
}

func (ac *AuthClient) SendMagicLinkHandler() http.HandlerFunc {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.CanLoginWithMagicLink() {
			// TODO: Add option to configure logger in Config
			slog.Error("FrontendRedirectURL is not set, it is required for magic link login")
			writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		sessionCookie, err := r.Cookie(ac.cookieName())
		if err == nil {
			_, err := ac.store.Session.Validate(r.Context(), nil, sessionCookie.Value)
			if err == nil {

				writeJSONError(w, http.StatusBadRequest, "User already logged in")
				return
			}
		}

		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			tx,
			ac.newVerification(
				auth.MagicLinkIntent,
				auth.NewNullString(req.Email),
				nil,
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.config.Mailer.SendMagicLinkEmail(req.Email, verificationToken); err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Magic link sent"})
	}
}

func (ac *AuthClient) CompleteMagicLinkSignInHandler(extractor ParamExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.CanLoginWithMagicLink() {
			// NOTE: this should not happen because mail should not be sent
			// when frontend redirect urls are not set
			slog.Error("Magic link frontend redirect urls not set, it is required for magic link login")
			writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			slog.Error("Token is required")
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		// Atomically validate and consume the token; a rollback below restores it.
		verificationToken, err := ac.store.Verification.Consume(r.Context(), tx, tokenStr, auth.MagicLinkIntent)
		if err != nil {
			slog.Error("Token is invalid")
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		// Email is required for magic link sign in to make sure we can create a user if it doesn't exist and find user by email if it does
		if !verificationToken.Email.Valid {
			slog.Error("Email is invalid")
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), nil, verificationToken.Email.String)
		if err != nil {
			// User does not exist, register the user with the email passed in the query string
			if errors.Is(err, store.ErrNotFound) {
				user = store.NewUser(
					verificationToken.Email.String,
					true,
					nil,
					nil,
					nil,
					nil,
				)

				cont, err := ac.hookStore.Trigger(
					r.Context(),
					NewAuthEvent(EventBeforeRegistration, w, r, user),
				)
				if err != nil {
					ac.FailedMagicLinkRedirect(w, r)
					return
				}
				if !cont {
					return
				}

				if err = ac.store.User.Create(r.Context(), tx, user); err != nil {
					ac.FailedMagicLinkRedirect(w, r)
					return
				}

				user, err = ac.store.User.GetByEmail(r.Context(), tx, verificationToken.Email.String)
				if err != nil {
					ac.FailedMagicLinkRedirect(w, r)
					return
				}

				cont, err = ac.hookStore.Trigger(
					r.Context(),
					NewAuthEvent(EventAfterRegistration, w, r, user),
				)
				if err != nil {
					ac.FailedMagicLinkRedirect(w, r)
					return
				}
				if !cont {
					return
				}

			} else {
				ac.FailedMagicLinkRedirect(w, r)
				return
			}
		}

		// Completing a magic link proves control of the inbox, which is the same
		// proof email verification relies on. Mark existing users verified too
		// (new users above are already created verified).
		if !user.EmailVerified {
			user.EmailVerified = true
			if user, err = ac.store.User.Update(r.Context(), tx, user); err != nil {
				ac.FailedMagicLinkRedirect(w, r)
				return
			}
		}

		sessionExpiresAt := ac.sessionExpiry()
		sessionToken, err := ac.store.Session.Create(r.Context(), tx, &store.Session{
			UserID:    user.ID,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
			ExpiresAt: sessionExpiresAt,
		})
		if err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		cookie := ac.newSessionCookie(sessionToken, sessionExpiresAt)
		http.SetCookie(w, cookie)

		ac.SuccessMagicLinkRedirect(w, r)
	}
}

func (ac *AuthClient) SendPasswordResetLinkHandler() http.HandlerFunc {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), nil, req.Email)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Don't reveal whether the email is registered.
				writeJSONResponse(w, http.StatusOK, map[string]any{"message": genericResetMessage})
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
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(EventPasswordResetInitialized, w, r, user),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !cont {
			return
		}

		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			tx,
			ac.newVerification(
				auth.PasswordResetIntent,
				nil,
				auth.NewNullString(user.ID),
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.config.Mailer.SendPasswordResetEmail(user.Email, verificationToken); err != nil {
			serverError(w, r, err)
			return
		}
		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": genericResetMessage})
	}
}

func (ac *AuthClient) CompletePasswordResetHandler(extractor ParamExtractor) http.HandlerFunc {
	type request struct {
		Password        string `json:"password" validate:"required,min=8,max=72"`
		ConfirmPassword string `json:"confirmPassword" validate:"eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		// Atomically validate and consume the token; a rollback below restores it.
		token, err := ac.store.Verification.Consume(r.Context(), tx, tokenStr, auth.PasswordResetIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}

		user, err := ac.store.User.GetByID(r.Context(), tx, token.UserID.String)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to get user")
			return
		}

		if err = user.Password.Set(req.Password); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to set password")
			return
		}
		if _, err = ac.store.User.Update(r.Context(), tx, user); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update password")
			return
		}

		// Invalidate all existing sessions so the reset locks out anyone holding an
		// old session (e.g. after an account compromise).
		if err = ac.store.Session.DeleteForUser(r.Context(), tx, user.ID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to revoke sessions")
			return
		}

		if err = ac.config.Mailer.SendPasswordChangedEmail(user.Email); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to send email")
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to commit changes")
			return
		}

		cont, err := ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(EventPasswordResetSuccess, w, r, user),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !cont {
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password reset successfully"})
	}
}

// ChangePasswordHandler lets an authenticated user change their password. It must be
// mounted behind AuthMiddleware. The current password is required as re-authentication
// so a hijacked session alone can't rotate the password. On success every other
// session is revoked (the current device is re-issued a fresh session) and the account
// is notified by email.
func (ac *AuthClient) ChangePasswordHandler() http.HandlerFunc {
	type request struct {
		CurrentPassword string `json:"currentPassword" validate:"required"`
		NewPassword     string `json:"newPassword" validate:"required,min=8,max=72"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=72,eqfield=NewPassword"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
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

		// OAuth-only and magic-link-only accounts have no password to change. Direct
		// them to the password-reset flow, which can set a first password.
		if len(user.Password) == 0 {
			writeJSONError(w, http.StatusBadRequest, "No password is set for this account. Use the password reset flow to set one.")
			return
		}

		if !user.Password.Compare(req.CurrentPassword) {
			writeJSONError(w, http.StatusBadRequest, "Current password is incorrect")
			return
		}

		if req.NewPassword == req.CurrentPassword {
			writeJSONError(w, http.StatusBadRequest, "New password must be different from the current password")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		if err = user.Password.Set(req.NewPassword); err != nil {
			serverError(w, r, err)
			return
		}
		if _, err = ac.store.User.Update(r.Context(), tx, user); err != nil {
			serverError(w, r, err)
			return
		}

		// Revoke every session (logs out other devices), then issue a fresh one for the
		// current device so this request stays authenticated.
		if err = ac.store.Session.DeleteForUser(r.Context(), tx, user.ID); err != nil {
			serverError(w, r, err)
			return
		}
		expiresAt := ac.sessionExpiry()
		newToken, err := ac.store.Session.Create(r.Context(), tx, &store.Session{
			UserID:    user.ID,
			IPAddress: r.RemoteAddr,
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

		http.SetCookie(w, ac.newSessionCookie(newToken, expiresAt))

		// Best-effort notification; a failure here must not fail the request.
		if mailErr := ac.config.Mailer.SendPasswordChangedEmail(user.Email); mailErr != nil {
			slog.Error("failed to send password changed email", "error", mailErr)
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password changed successfully"})
	}
}

// ChangeEmailHandler lets an authenticated user request an email change. It must be
// mounted behind AuthMiddleware. The change is not applied here: a confirmation link is
// sent to the NEW address and the change only takes effect when ConfirmEmailChangeHandler
// consumes that token, so the account email is never set to an unverified address.
//
// OAuth-linked accounts are rejected: OAuthCallbackHandler matches returning users by
// email, so changing it would orphan the account on the next OAuth sign-in. Password
// accounts must re-authenticate with their current password; magic-link-only accounts
// have no password, so their session plus the new-email verification is the control.
func (ac *AuthClient) ChangeEmailHandler() http.HandlerFunc {
	type request struct {
		NewEmail        string `json:"newEmail" validate:"required,email,max=255"`
		CurrentPassword string `json:"currentPassword" validate:"omitempty,max=72"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
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

		if user.OAuthProvider != nil && user.OAuthProvider.Valid {
			writeJSONError(w, http.StatusConflict, "Your email is managed by your linked "+user.OAuthProvider.String+" account and can't be changed here.")
			return
		}

		// Re-authenticate accounts that have a password. Magic-link-only accounts have
		// none; for them the session and the new-email verification are the control.
		if len(user.Password) > 0 && !user.Password.Compare(req.CurrentPassword) {
			writeJSONError(w, http.StatusBadRequest, "Current password is incorrect")
			return
		}

		if strings.EqualFold(req.NewEmail, user.Email) {
			writeJSONError(w, http.StatusBadRequest, "The new email is the same as your current email")
			return
		}

		// Reject an address already registered to another account.
		if _, err := ac.store.User.GetByEmail(r.Context(), nil, req.NewEmail); err == nil {
			writeJSONError(w, http.StatusConflict, "That email address is already in use")
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			serverError(w, r, err)
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		// The token carries the pending new email; the user_id ties it to this account.
		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			tx,
			ac.newVerification(
				auth.EmailChangeIntent,
				auth.NewNullString(req.NewEmail),
				auth.NewNullString(user.ID),
			),
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.config.Mailer.SendEmailChangeEmail(req.NewEmail, verificationToken); err != nil {
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "A confirmation link has been sent to your new email address."})
	}
}

// ConfirmEmailChangeHandler applies an email change once the user visits the link sent
// to their new address. It is a public endpoint authorized solely by the single-use
// token, so it must not be mounted behind AuthMiddleware.
func (ac *AuthClient) ConfirmEmailChangeHandler(extractor ParamExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				if rbErr := ac.store.Transaction.Rollback(tx); rbErr != nil {
					slog.Error("rollback error", "error", rbErr)
				}
			}
		}(tx)

		// Atomically validate and consume the token; a rollback below restores it.
		token, err := ac.store.Verification.Consume(r.Context(), tx, tokenStr, auth.EmailChangeIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid || !token.Email.Valid {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		user, err := ac.store.User.GetByID(r.Context(), tx, token.UserID.String)
		if err != nil {
			serverError(w, r, err)
			return
		}

		user.Email = token.Email.String
		user.EmailVerified = true
		if _, err = ac.store.User.Update(r.Context(), tx, user); err != nil {
			// The address may have been taken between request and confirmation.
			if errors.Is(err, store.ErrDuplicateEmail) {
				writeJSONError(w, http.StatusConflict, "That email address is already in use")
				return
			}
			serverError(w, r, err)
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Email changed successfully"})
	}
}

func (ac *AuthClient) OAuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			slog.Error("oauth completion failed", "error", err)
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}

		var cont bool
		defer func(tx *sqlx.Tx) {
			if err != nil || !cont {
				err := ac.store.Transaction.Rollback(tx)
				slog.Error("rollback error", "error", err.Error())
			}
		}(tx)

		user, err := ac.store.User.GetByEmail(r.Context(), nil, gothUser.Email)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// User does not exist, create a new one
				user = &store.User{
					Email:         gothUser.Email,
					AvatarURL:     auth.NewNullString(gothUser.AvatarURL),
					AvatarSource:  auth.NewNullString("oauth"),
					EmailVerified: true,
					OAuthProvider: auth.NewNullString(gothUser.Provider),
					OAuthID:       auth.NewNullString(gothUser.UserID),
				}

				cont, err = ac.hookStore.Trigger(
					r.Context(),
					NewAuthEvent(EventBeforeRegistration, w, r, user),
				)
				if err != nil {
					serverError(w, r, err)
					return
				}
				if !cont {
					return
				}

				if err = ac.store.User.Create(r.Context(), tx, user); err != nil {
					serverError(w, r, err)
					return
				}

				user, err = ac.store.User.GetByEmail(r.Context(), tx, gothUser.Email)
				if err != nil {
					serverError(w, r, err)
					return
				}

				cont, err = ac.hookStore.Trigger(
					r.Context(),
					NewAuthEvent(EventAfterRegistration, w, r, user),
				)
				if err != nil {
					serverError(w, r, err)
				}
				if !cont {
					return
				}

			} else {
				serverError(w, r, err)
				return
			}
		}

		// User exists, update OAuth provider and ID. The field is nil when the column
		// is NULL (e.g. an existing password-only account), which counts as "not set".
		if user.OAuthProvider == nil || !user.OAuthProvider.Valid || user.OAuthProvider.String != gothUser.Provider {
			user.OAuthProvider = auth.NewNullString(gothUser.Provider)
			user.OAuthID = auth.NewNullString(gothUser.UserID)
			user.EmailVerified = true
			user, err = ac.store.User.Update(r.Context(), tx, user)
			if err != nil {
				serverError(w, r, err)
				return
			}
		}

		// Update avatar URL if it's from OAuth provider or not set (nil = NULL = not set).
		if user.AvatarSource == nil || !user.AvatarSource.Valid || user.AvatarSource.String == "oauth" {
			user.AvatarURL = auth.NewNullString(gothUser.AvatarURL)
			user.AvatarSource = auth.NewNullString("oauth")
			user, err = ac.store.User.Update(r.Context(), tx, user)
			if err != nil {
				serverError(w, r, err)
				return
			}
		}

		sessionExpiresAt := ac.sessionExpiry()
		token, err := ac.store.Session.Create(
			r.Context(),
			tx,
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: sessionExpiresAt,
			},
		)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if err = tx.Commit(); err != nil {
			serverError(w, r, err)
			return
		}

		http.SetCookie(w, ac.newSessionCookie(token, sessionExpiresAt))

		cont, err = ac.hookStore.Trigger(
			r.Context(),
			NewAuthEvent(EventOAuthSuccess, w, r, user),
		)
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
