package core

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/jmoiron/sqlx"
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

		err = ac.store.User.Create(r.Context(), newUser, tx)
		if err != nil && err != store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err != nil && err == store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusBadRequest, "Email already taken")
			return
		}

		user, err := ac.store.User.GetByEmail(r.Context(), req.Email, tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		var token string
		if ac.config.Session.LoginAfterRegister {
			token, err = ac.store.Session.Create(
				r.Context(),
				&store.Session{
					UserID:    user.ID,
					IPAddress: r.RemoteAddr,
					UserAgent: r.UserAgent(),
					ExpiresAt: time.Now().Add(24 * time.Hour),
				},
				tx,
			)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		verificationToken, err := ac.store.Verification.Create(
			r.Context(),
			store.NewVerification(
				auth.EmailVerificationIntent,
				nil,
				auth.NewNullString(user.ID),
			),
			tx,
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
			_, err := ac.store.Session.Validate(r.Context(), sessCookie.Value)
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

		user, err := ac.store.User.GetByEmail(r.Context(), req.Email, nil)
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
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			nil,
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
		err = ac.store.Session.Delete(r.Context(), token.Value, nil)
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

		token, err := ac.store.Verification.Validate(r.Context(), tokenStr, auth.EmailVerificationIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}
		user, err := ac.store.User.GetByID(r.Context(), token.UserID.String, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user.EmailVerified = true
		_, err = ac.store.User.Update(r.Context(), user, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = ac.store.Verification.Delete(r.Context(), token.Value, nil)
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
		if ac.config.Session.FrontendRedirectURL == "" {
			// TODO: Add option to configure logger in Config
			slog.Error("FrontendRedirectURL is not set, it is required for magic link login")
			writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		sessionCookie, err := r.Cookie("session")
		if err == nil {
			_, err := ac.store.Session.Validate(r.Context(), sessionCookie.Value)
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
			store.NewVerification(
				auth.MagicLinkIntent,
				auth.NewNullString(req.Email),
				nil,
			),
			tx,
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
		tokenStr := extractor.GetParam("token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		verificationToken, err := ac.store.Verification.Validate(r.Context(), tokenStr, auth.MagicLinkIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		// Email is required for magic link sign in to make sure we can create a user if it doesn't exist and find user by email if it does
		if !verificationToken.Email.Valid {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				ac.store.Transaction.Rollback(tx)
			}
		}(tx)

		user, err := ac.store.User.GetByEmail(r.Context(), verificationToken.Email.String, nil)

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
				if err = ac.store.User.Create(r.Context(), user, tx); err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}

				user, err = ac.store.User.GetByEmail(r.Context(), verificationToken.Email.String, tx)
				if err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		sessionToken, err := ac.store.Session.Create(r.Context(), &store.Session{
			UserID:    user.ID,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = ac.store.Transaction.Commit(tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cookie := auth.NewSessionCookie(sessionToken)
		http.SetCookie(w, cookie)

		if ac.config.Session.FrontendRedirectURL == "" {
			// TODO: update when logger is configured
			slog.Error("FrontendRedirectURL is not set, it is required for magic link login")
			writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		http.Redirect(w, r, ac.config.Session.FrontendRedirectURL, http.StatusSeeOther)
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

		user, err := ac.store.User.GetByEmail(r.Context(), req.Email, nil)
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
			store.NewVerification(
				auth.PasswordResetIntent,
				nil,
				auth.NewNullString(user.ID),
			),
			tx,
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

		token, err := ac.store.Verification.Validate(r.Context(), tokenStr, auth.PasswordResetIntent)
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

		user, err := ac.store.User.GetByID(r.Context(), token.UserID.String, nil)
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
		if _, err = ac.store.User.Update(r.Context(), user, tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update password")
			return
		}

		if err = ac.store.Verification.Delete(r.Context(), token.Value, tx); err != nil {
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
