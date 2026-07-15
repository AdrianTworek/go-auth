package gorilla_adapter

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type GorillaParamExtractor struct {
	Vars map[string]string
}

func (g *GorillaParamExtractor) GetParam(key string) string {
	return g.Vars[key]
}

func InitAuth(ac *core.AuthClient, r *mux.Router) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}
	// Protected handlers are pre-wrapped with the auth middleware, so /me and /logout
	// need no subrouter with a Use call.
	mw := ac.AuthMiddleware()

	r.Handle(core.PathRegister, ac.RegisterHandler()).Methods(http.MethodPost)
	r.Handle(core.PathLogin, ac.LoginHandler()).Methods(http.MethodPost)
	r.HandleFunc(core.PathVerifyEmail, func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&GorillaParamExtractor{Vars: mux.Vars(r)}).ServeHTTP(w, r)
	}).Methods(http.MethodGet)
	r.Handle(core.PathResendVerification, ac.ResendVerificationHandler()).Methods(http.MethodPost)
	r.HandleFunc(core.PathConfirmEmailChange, func(w http.ResponseWriter, r *http.Request) {
		ac.ConfirmEmailChangeHandler(&GorillaParamExtractor{Vars: mux.Vars(r)}).ServeHTTP(w, r)
	}).Methods(http.MethodGet)

	if ac.CanLoginWithOAuth() {
		r.HandleFunc(core.PathOAuthBegin, gothic.BeginAuthHandler).Methods(http.MethodGet)
		r.Handle(core.PathOAuthCallback, ac.OAuthCallbackHandler()).Methods(http.MethodGet)
	}

	if ac.CanLoginWithMagicLink() {
		r.Handle(core.PathSendMagicLink, ac.SendMagicLinkHandler()).Methods(http.MethodPost)
		r.HandleFunc(core.PathMagicLink, func(w http.ResponseWriter, r *http.Request) {
			ac.CompleteMagicLinkSignInHandler(&GorillaParamExtractor{Vars: mux.Vars(r)}).ServeHTTP(w, r)
		}).Methods(http.MethodGet)
	}

	r.Handle(core.PathSendPasswordReset, ac.SendPasswordResetLinkHandler()).Methods(http.MethodPost)
	r.HandleFunc(core.PathPasswordReset, func(w http.ResponseWriter, r *http.Request) {
		ac.CompletePasswordResetHandler(&GorillaParamExtractor{Vars: mux.Vars(r)}).ServeHTTP(w, r)
	}).Methods(http.MethodPut)

	r.Handle(core.PathMe, mw(ac.GetMeHandler())).Methods(http.MethodGet)
	r.Handle(core.PathLogout, mw(ac.LogoutHandler())).Methods(http.MethodPost)
	r.Handle(core.PathChangePassword, mw(ac.ChangePasswordHandler())).Methods(http.MethodPost)
	r.Handle(core.PathChangeEmail, mw(ac.ChangeEmailHandler())).Methods(http.MethodPost)
}
