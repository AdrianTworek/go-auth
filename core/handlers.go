package core

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth/gothic"
)

func (ac *AuthClient) RegisterHandler() http.HandlerFunc {
	type registerRequest struct {
		Email           string `json:"email" validate:"required,min=3,max=255,email"`
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=30,eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		newUser := store.NewUser(req.Email, false, nil, nil, nil, nil)
		if err := newUser.Password.Set(req.Password); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

		err = ac.store.User.Create(r.Context(), tx, newUser)
		if err != nil && err != store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err != nil && err == store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusBadRequest, "Email already taken")
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), tx, req.Email)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		var token string
		if ac.config.Session.LoginAfterRegister {
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
				writeJSONError(w, http.StatusInternalServerError, err.Error())
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = ac.config.Mailer.SendVerificationEmail(user.Email, verificationToken)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}

		if token != "" && ac.config.Session.LoginAfterRegister {
			cookie := auth.NewSessionCookie(token)
			http.SetCookie(w, cookie)
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
		sessCookie, err := r.Cookie("session")
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

		user, err := ac.store.User.GetByEmail(r.Context(), nil, req.Email)
		if err != nil && err != store.ErrNotFound {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err != nil && err == store.ErrNotFound {
			writeJSONError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		if !user.Password.Compare(req.Password) {
			writeJSONError(w, http.StatusUnauthorized, "Invalid credentials")
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cookie := auth.NewSessionCookie(token)
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}

func (ac *AuthClient) GetMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromContext(r)
		writeJSONResponse(w, http.StatusOK, map[string]*store.User{"user": user})
	}
}

func (ac *AuthClient) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("session")
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		err = ac.store.Session.Delete(r.Context(), nil, token.Value)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cookie := auth.DeleteSessionCookie()
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged out successfully"})
	}
}

func (ac *AuthClient) VerifyEmailHandler(extractor ParamExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		token, err := ac.store.Verification.Validate(r.Context(), nil, tokenStr, auth.EmailVerificationIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}
		user, err := ac.store.User.GetByID(r.Context(), nil, token.UserID.String)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user.EmailVerified = true
		_, err = ac.store.User.Update(r.Context(), nil, user)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = ac.store.Verification.Delete(r.Context(), nil, token.Value)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
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
		sessionCookie, err := r.Cookie("session")
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err = ac.config.Mailer.SendMagicLinkEmail(req.Email, verificationToken); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
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

		verificationToken, err := ac.store.Verification.Validate(r.Context(), nil, tokenStr, auth.MagicLinkIntent)
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

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

		user, err := ac.store.User.GetByEmail(r.Context(), nil, verificationToken.Email.String)

		if err != nil {
			// User does not exist, register the user with the email passed in the query string
			if err == store.ErrNotFound {
				user = store.NewUser(
					verificationToken.Email.String,
					true,
					nil,
					nil,
					nil,
					nil,
				)
				if err = ac.store.User.Create(r.Context(), tx, user); err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}

				user, err = ac.store.User.GetByEmail(r.Context(), tx, verificationToken.Email.String)
				if err != nil {
					ac.FailedMagicLinkRedirect(w, r)
					return
				}
			} else {
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

		if err = ac.store.Verification.Delete(r.Context(), tx, verificationToken.Value); err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			ac.FailedMagicLinkRedirect(w, r)
			return
		}

		cookie := auth.NewSessionCookie(sessionToken)
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
		if err != nil && err != store.ErrNotFound {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		if err != nil && err == store.ErrNotFound {
			writeJSONError(w, http.StatusBadRequest, "User not found")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err = ac.config.Mailer.SendPasswordResetEmail(user.Email, verificationToken); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err = ac.store.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password reset link sent"})
	}
}

func (ac *AuthClient) CompletePasswordResetHandler(extractor ParamExtractor) http.HandlerFunc {
	type request struct {
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		token, err := ac.store.Verification.Validate(r.Context(), nil, tokenStr, auth.PasswordResetIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}
		var req request
		if err := readAndValidateJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := ac.store.User.GetByID(r.Context(), nil, token.UserID.String)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to get user")
			return
		}

		tx, err := ac.store.Transaction.Begin()

		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

		user.Password.Set(req.Password)
		if _, err = ac.store.User.Update(r.Context(), tx, user); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update password")
			return
		}

		if err = ac.store.Verification.Delete(r.Context(), tx, token.Value); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to delete token")
			return
		}

		if err = ac.config.Mailer.SendPasswordChangedEmail(user.Email); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to send email")
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to commit changes")
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password reset successfully"})
	}
}

func (ac *AuthClient) OAuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		tx, err := ac.store.Transaction.Begin()

		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), nil, gothUser.Email)

		if err != nil {
			if err == store.ErrNotFound {
				// User does not exist, create a new one
				user = &store.User{
					Email:         gothUser.Email,
					AvatarURL:     auth.NewNullString(gothUser.AvatarURL),
					AvatarSource:  auth.NewNullString("oauth"),
					EmailVerified: true,
					OAuthProvider: auth.NewNullString(gothUser.Provider),
					OAuthID:       auth.NewNullString(gothUser.UserID),
				}
				if err = ac.store.User.Create(r.Context(), tx, user); err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}

				user, err = ac.store.User.GetByEmail(r.Context(), tx, gothUser.Email)
				if err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		// User exists, update OAuth provider and ID
		if !user.OAuthProvider.Valid || user.OAuthProvider.String != gothUser.Provider {
			user.OAuthProvider = auth.NewNullString(gothUser.Provider)
			user.OAuthID = auth.NewNullString(gothUser.UserID)
			user.EmailVerified = true
			user, err = ac.store.User.Update(r.Context(), tx, user)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		// Update avatar URL if it's from OAuth provider or not set
		if !user.AvatarSource.Valid || user.AvatarSource.String == "oauth" {
			user.AvatarURL = auth.NewNullString(gothUser.AvatarURL)
			user.AvatarSource = auth.NewNullString("oauth")
			user, err = ac.store.User.Update(r.Context(), tx, user)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err = tx.Commit(); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		http.SetCookie(w, auth.NewSessionCookie(token))

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}
