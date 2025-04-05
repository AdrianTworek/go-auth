package core

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

func (ac *AuthClient) AuthMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := r.Cookie("session")
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			session, err := ac.store.Session.Validate(r.Context(), token.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			// Skip session refresh for logout requests
			if !strings.HasSuffix(r.URL.Path, "/logout") {
				if time.Until(session.ExpiresAt) < auth.SessionRefreshThreshold {
					newToken, err := ac.store.Session.Refresh(r.Context(), token.Value)
					if err != nil {
						writeJSONError(w, http.StatusInternalServerError, "failed to refresh session")
						return
					}

					http.SetCookie(w, auth.NewSessionCookie(newToken))
				}
			}

			user, err := ac.store.User.GetByID(r.Context(), session.UserID, nil)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), ctxUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
