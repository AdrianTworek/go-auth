package core

import (
	"context"
	"net/http"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

func (ac *AuthClient) AuthMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := r.Cookie(ac.cookieName())
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			session, err := ac.store.Session.Validate(r.Context(), nil, token.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			// Slide the session when it's close to expiry. The effective token is
			// tracked so downstream handlers (e.g. logout) act on the current token
			// even after a rotation.
			effectiveToken := token.Value
			if time.Until(session.ExpiresAt) < auth.SessionRefreshThreshold {
				newToken, err := ac.store.Session.Refresh(r.Context(), nil, token.Value)
				if err != nil {
					serverError(w, r, err)
					return
				}

				http.SetCookie(w, ac.newSessionCookie(newToken))
				effectiveToken = newToken
			}

			user, err := ac.store.User.GetByID(r.Context(), nil, session.UserID)
			if err != nil {
				serverError(w, r, err)
				return
			}

			ctx := context.WithValue(r.Context(), ctxUserKey, user)
			ctx = context.WithValue(ctx, ctxSessionTokenKey, effectiveToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
