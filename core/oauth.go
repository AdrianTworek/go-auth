package core

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// OAuthCallbackHandler completes an OAuth flow. It does one of two things depending on
// who is asking: with no session it signs a user in, and with a session it attaches the
// provider account to the signed-in user instead.
//
// Identity on sign-in is the provider's own account identifier, never the email address
// the provider asserted. A matching email is only ever a *candidate* for attaching the
// provider to an existing account, and only for providers the operator has declared
// trustworthy — otherwise a provider that lets its users choose an arbitrary address
// would be a route into somebody else's account.
//
// It must stay a public route, since a signed-out user has to be able to complete a
// sign-in, so it reads the session cookie itself rather than sitting behind
// AuthMiddleware.
func (ac *AuthClient) OAuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			slog.Error("oauth completion failed", "error", err)
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if user, ok := ac.userFromSessionCookie(r); ok {
			ac.oauthLink(w, r, user, gothUser)
			return
		}
		ac.oauthSignIn(w, r, gothUser)
	}
}

// userFromSessionCookie resolves the caller from the session cookie without the
// middleware, for the one route that is mounted publicly but behaves differently when
// someone is signed in.
func (ac *AuthClient) userFromSessionCookie(r *http.Request) (*store.User, bool) {
	cookie, err := r.Cookie(ac.cookieName())
	if err != nil {
		return nil, false
	}
	session, err := ac.store.Session.Validate(r.Context(), nil, cookie.Value)
	if err != nil {
		return nil, false
	}
	user, err := ac.store.User.GetByID(r.Context(), nil, session.UserID)
	if err != nil {
		return nil, false
	}
	return user, true
}

// autoLinkAllowed reports whether a provider's asserted email may be used to attach it to
// an existing account. The default is an empty trust list, so the safe behaviour is what
// an operator gets before thinking about it.
func (ac *AuthClient) autoLinkAllowed(provider string) bool {
	if ac.config.OAuth == nil {
		return false
	}
	for _, trusted := range ac.config.OAuth.TrustedProviders {
		if trusted == provider {
			return true
		}
	}
	return false
}

func accountAlreadyLinkedMessage(provider string) string {
	return "That " + provider + " account is already linked to a different account"
}

// oauthLink attaches a provider account to the signed-in user. An account already
// attached to somebody else is refused rather than moved: reassigning it would quietly
// take away that user's way of signing in.
func (ac *AuthClient) oauthLink(w http.ResponseWriter, r *http.Request, user *store.User, gothUser goth.User) {
	existing, err := ac.store.Account.GetByProviderAccount(r.Context(), nil, gothUser.Provider, gothUser.UserID)
	switch {
	case err == nil && existing.UserID == user.ID:
		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "This provider is already linked to your account"})
		return
	case err == nil:
		writeJSONError(w, http.StatusConflict, accountAlreadyLinkedMessage(gothUser.Provider))
		return
	case !errors.Is(err, store.ErrNotFound):
		serverError(w, r, err)
		return
	}

	account, err := ac.store.Account.Create(r.Context(), nil, newAccountFor(user.ID, gothUser))
	if err != nil {
		if errors.Is(err, store.ErrAccountLinked) {
			writeJSONError(w, http.StatusConflict, accountAlreadyLinkedMessage(gothUser.Provider))
			return
		}
		serverError(w, r, err)
		return
	}

	if !ac.auditAccountLinked(w, r, user, account) {
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Provider linked successfully"})
}

// oauthSignIn resolves who is signing in, in the only order that is safe:
//
//  1. a known provider account is the authoritative identity;
//  2. otherwise a matching email is a candidate, allowed only for a trusted provider;
//  3. otherwise this is a new user.
func (ac *AuthClient) oauthSignIn(w http.ResponseWriter, r *http.Request, gothUser goth.User) {
	account, err := ac.store.Account.GetByProviderAccount(r.Context(), nil, gothUser.Provider, gothUser.UserID)
	if err == nil {
		user, userErr := ac.store.User.GetByID(r.Context(), nil, account.UserID)
		if userErr != nil {
			serverError(w, r, userErr)
			return
		}
		ac.oauthCompleteSignIn(w, r, user, gothUser, false)
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		serverError(w, r, err)
		return
	}

	existing, err := ac.store.User.GetByEmail(r.Context(), nil, gothUser.Email)
	switch {
	case err == nil:
		if !ac.autoLinkAllowed(gothUser.Provider) {
			// Refusing is what closes the takeover path. Creating a second user is not an
			// alternative: the email column is unique, and that uniqueness is load-bearing
			// for password login. Nothing is written and no session is issued.
			writeJSONError(w, http.StatusConflict,
				"An account with this email address already exists. Sign in with your existing method, "+
					"then link "+gothUser.Provider+" from your account settings.")
			return
		}
		ac.oauthCompleteSignIn(w, r, existing, gothUser, true)
		return
	case !errors.Is(err, store.ErrNotFound):
		serverError(w, r, err)
		return
	}

	ac.oauthRegister(w, r, gothUser)
}

func newAccountFor(userID string, gothUser goth.User) *store.Account {
	return &store.Account{
		UserID:            userID,
		Provider:          gothUser.Provider,
		ProviderAccountID: gothUser.UserID,
		Email:             auth.NewNullString(gothUser.Email),
	}
}

// applyProviderAttributes copies what the provider tells us onto the user: the email is
// verified by definition, and the avatar is refreshed unless the user has overridden it.
//
// It also keeps the legacy single-provider columns in step. Those columns are the thing
// this feature replaces, but they survive the expand half of the migration so it stays
// revertible; the contract migration drops them and this with it.
func applyProviderAttributes(user *store.User, gothUser goth.User) {
	user.OAuthProvider = auth.NewNullString(gothUser.Provider)
	user.OAuthID = auth.NewNullString(gothUser.UserID)
	user.EmailVerified = true

	if user.AvatarSource == nil || !user.AvatarSource.Valid || user.AvatarSource.String == "oauth" {
		user.AvatarURL = auth.NewNullString(gothUser.AvatarURL)
		user.AvatarSource = auth.NewNullString("oauth")
	}
}

func (ac *AuthClient) issueOAuthSession(r *http.Request, tx *sqlx.Tx, userID string) (string, time.Time, error) {
	expiresAt := ac.sessionExpiry()
	token, err := ac.store.Session.Create(r.Context(), tx, &store.Session{
		UserID:    userID,
		IPAddress: ac.clientIP(r),
		UserAgent: r.UserAgent(),
		ExpiresAt: expiresAt,
	})
	return token, expiresAt, err
}

// rollbackUnless rolls the transaction back unless it was committed. Returned as a
// deferred closure so each orchestration reads the same way.
func (ac *AuthClient) rollbackUnless(tx *sqlx.Tx, committed *bool) func() {
	return func() {
		if *committed {
			return
		}
		if err := ac.store.Transaction.Rollback(tx); err != nil {
			slog.Error("rollback error", "error", err)
		}
	}
}

// oauthCompleteSignIn signs in a user who already exists, optionally creating the
// provider link first (the trusted auto-link case).
func (ac *AuthClient) oauthCompleteSignIn(
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	gothUser goth.User,
	createLink bool,
) {
	tx, err := ac.store.Transaction.Begin()
	if err != nil {
		serverError(w, r, err)
		return
	}
	committed := false
	defer ac.rollbackUnless(tx, &committed)()

	var linked *store.Account
	if createLink {
		linked, err = ac.store.Account.Create(r.Context(), tx, newAccountFor(user.ID, gothUser))
		if err != nil {
			if errors.Is(err, store.ErrAccountLinked) {
				writeJSONError(w, http.StatusConflict, accountAlreadyLinkedMessage(gothUser.Provider))
				return
			}
			serverError(w, r, err)
			return
		}
	}

	applyProviderAttributes(user, gothUser)
	user, err = ac.store.User.Update(r.Context(), tx, user)
	if err != nil {
		serverError(w, r, err)
		return
	}

	token, expiresAt, err := ac.issueOAuthSession(r, tx, user.ID)
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

	if linked != nil && !ac.auditAccountLinked(w, r, user, linked) {
		return
	}
	ac.oauthSuccess(w, r, user)
}

// oauthRegister creates a user and their first provider link together, then signs them in.
func (ac *AuthClient) oauthRegister(w http.ResponseWriter, r *http.Request, gothUser goth.User) {
	user := &store.User{Email: gothUser.Email}
	applyProviderAttributes(user, gothUser)

	cont, err := ac.hookStore.Trigger(r.Context(), NewAuthEvent(EventBeforeRegistration, w, r, user))
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !cont {
		return
	}

	tx, err := ac.store.Transaction.Begin()
	if err != nil {
		serverError(w, r, err)
		return
	}
	committed := false
	defer ac.rollbackUnless(tx, &committed)()

	if err = ac.store.User.Create(r.Context(), tx, user); err != nil {
		serverError(w, r, err)
		return
	}
	user, err = ac.store.User.GetByEmail(r.Context(), tx, gothUser.Email)
	if err != nil {
		serverError(w, r, err)
		return
	}

	linked, err := ac.store.Account.Create(r.Context(), tx, newAccountFor(user.ID, gothUser))
	if err != nil {
		if errors.Is(err, store.ErrAccountLinked) {
			writeJSONError(w, http.StatusConflict, accountAlreadyLinkedMessage(gothUser.Provider))
			return
		}
		serverError(w, r, err)
		return
	}

	token, expiresAt, err := ac.issueOAuthSession(r, tx, user.ID)
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

	cont, err = ac.hookStore.Trigger(r.Context(), NewAuthEvent(EventAfterRegistration, w, r, user))
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !cont {
		return
	}

	if !ac.auditAccountLinked(w, r, user, linked) {
		return
	}
	ac.oauthSuccess(w, r, user)
}

func (ac *AuthClient) oauthSuccess(w http.ResponseWriter, r *http.Request, user *store.User) {
	cont, err := ac.hookStore.Trigger(r.Context(), NewAuthEvent(EventOAuthSuccess, w, r, user))
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !cont {
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
}
