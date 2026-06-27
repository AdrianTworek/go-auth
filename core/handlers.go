package core

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// genericResetMessage is returned by the send-reset endpoint whether or
// not the email is registered, so the response never reveals account existence.
const genericResetMessage = "If an account with that email exists, a password reset link has been sent."

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
		if ac.config.Session.LoginAfterRegister && !ac.config.Session.RequireVerifiedEmail {
			token, err = ac.store.Session.Create(
				r.Context(),
				tx,
				&store.Session{
					UserID:    user.ID,
					IPAddress: r.RemoteAddr,
					UserAgent: r.UserAgent(),
					ExpiresAt: time.Now().Add(24 * time.Hour),
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
			store.NewVerification(
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
			cookie := ac.newSessionCookie(token)
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

		token, err := ac.store.Session.Create(
			r.Context(),
			nil,
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		)
		if err != nil {
			serverError(w, r, err)
			return
		}

		cookie := ac.newSessionCookie(token)
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
			store.NewVerification(
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

		sessionToken, err := ac.store.Session.Create(r.Context(), tx, &store.Session{
			UserID:    user.ID,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
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

		cookie := ac.newSessionCookie(sessionToken)
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
			store.NewVerification(
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

		token, err := ac.store.Session.Create(
			r.Context(),
			tx,
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
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

		http.SetCookie(w, ac.newSessionCookie(token))

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
