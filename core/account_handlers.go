package core

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// accountView is the safe projection of a linked account. The provider's own account
// identifier is deliberately omitted: a caller tells two links at the same provider apart
// by their email, and the provider-side id is of no use to them.
type accountView struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

// ListAccountsHandler returns the authenticated user's linked providers, newest first.
// It must be mounted behind AuthMiddleware.
func (ac *AuthClient) ListAccountsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		accounts, err := ac.store.Account.ListForUser(r.Context(), user.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}

		views := make([]accountView, 0, len(accounts))
		for _, a := range accounts {
			email := ""
			if a.Email != nil && a.Email.Valid {
				email = a.Email.String
			}
			views = append(views, accountView{
				ID:        a.ID,
				Provider:  a.Provider,
				Email:     email,
				CreatedAt: a.CreatedAt,
			})
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"accounts": views})
	}
}

// UnlinkAccountHandler detaches one linked provider from the authenticated user. It must
// be mounted behind AuthMiddleware.
//
// Like revoke-one-session, the id is read from the request path rather than through a
// ParamExtractor, so every adapter mounts it exactly like any other protected route.
// Deletion is scoped to the caller, and an unknown, foreign or malformed id all answer
// 404 so the endpoint can't be used to probe for existence.
func (ac *AuthClient) UnlinkAccountHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		id := strings.TrimPrefix(r.URL.Path, PathAccounts+"/")
		if id == "" || strings.Contains(id, "/") {
			writeJSONError(w, http.StatusBadRequest, "Account id is required")
			return
		}

		tx, err := ac.store.Transaction.Begin()
		if err != nil {
			serverError(w, r, err)
			return
		}
		committed := false
		defer ac.rollbackUnless(tx, &committed)()

		// Lock the user for the rest of the transaction so that two concurrent unlinks
		// cannot each observe one sign-in method remaining and both proceed.
		if err = ac.store.User.LockForUpdate(r.Context(), tx, user.ID); err != nil {
			serverError(w, r, err)
			return
		}

		deleted, err := ac.store.Account.DeleteByIDForUser(r.Context(), tx, user.ID, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "Account not found")
				return
			}
			serverError(w, r, err)
			return
		}

		// Delete first, then check what is left: that way a bogus id still answers 404
		// rather than revealing, through a 409, that the caller has exactly one link.
		remaining, err := ac.store.Account.CountForUser(r.Context(), tx, user.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if remaining == 0 && len(user.Password) == 0 {
			// Rolling back leaves the link in place: removing it would lock the user out
			// of their own account, which is worse than refusing.
			writeJSONError(w, http.StatusConflict,
				"This is the only way you can sign in. Set a password or link another provider before removing it.")
			return
		}

		if err = ac.store.Transaction.Commit(tx); err != nil {
			serverError(w, r, err)
			return
		}
		committed = true

		if !ac.auditAccountUnlinked(w, r, user, deleted) {
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Provider unlinked"})
	}
}
