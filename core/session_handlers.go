package core

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// sessionView is the safe projection of a session returned by the list endpoint. It
// deliberately omits the stored token hash and exposes only what a user needs to
// recognise a device ("is this me?", where and when it signed in).
type sessionView struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Current marks the session backing this very request, so a UI can label it and
	// avoid offering to revoke the device the user is on.
	Current bool `json:"current"`
}

// ListSessionsHandler returns the authenticated user's active sessions, newest first,
// with the current session flagged. It must be mounted behind AuthMiddleware.
func (ac *AuthClient) ListSessionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		currentToken, _ := getSessionTokenFromContext(r)
		currentHash := auth.HashToken(currentToken)

		sessions, err := ac.store.Session.ListForUser(r.Context(), user.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}

		views := make([]sessionView, 0, len(sessions))
		for _, s := range sessions {
			views = append(views, sessionView{
				ID:        s.ID,
				IPAddress: s.IPAddress,
				UserAgent: s.UserAgent,
				CreatedAt: s.CreatedAt,
				ExpiresAt: s.ExpiresAt,
				Current:   s.Token == currentHash,
			})
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"sessions": views})
	}
}

// RevokeOtherSessionsHandler logs the user out of every device except the current one
// ("sign out everywhere else"). It must be mounted behind AuthMiddleware.
func (ac *AuthClient) RevokeOtherSessionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		currentToken, ok := getSessionTokenFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if err := ac.store.Session.DeleteOthersForUser(r.Context(), nil, user.ID, currentToken); err != nil {
			serverError(w, r, err)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "All other sessions have been revoked"})
	}
}

// RevokeSessionHandler revokes one of the user's sessions by id (e.g. "sign out this
// other device"). It must be mounted behind AuthMiddleware.
//
// The id is read from the request path rather than through a ParamExtractor: the route
// is always mounted at PathSession, so trimming that fixed prefix yields the id and
// lets every adapter register this route exactly like the other protected routes,
// without a per-framework param-extraction closure. Deletion is scoped to the caller's
// user id, so one user can't revoke another's session (an unknown id returns 404).
func (ac *AuthClient) RevokeSessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		currentToken, _ := getSessionTokenFromContext(r)

		id := strings.TrimPrefix(r.URL.Path, PathSessions+"/")
		if id == "" || strings.Contains(id, "/") {
			writeJSONError(w, http.StatusBadRequest, "Session id is required")
			return
		}

		deleted, err := ac.store.Session.DeleteByIDForUser(r.Context(), nil, user.ID, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "Session not found")
				return
			}
			serverError(w, r, err)
			return
		}

		// Revoking the session behind this request logs the caller out, so clear the
		// cookie as well.
		if deleted.Token == auth.HashToken(currentToken) {
			http.SetCookie(w, ac.deleteSessionCookie())
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Session revoked"})
	}
}
