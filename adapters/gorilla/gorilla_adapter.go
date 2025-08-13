package gorilla_adapter

import (
	"net/http"

	"github.com/AdrianTworek/go-auth/core"
	"github.com/gorilla/mux"
	"github.com/markbates/goth/gothic"
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

	publicRouter := r.PathPrefix("/auth").Subrouter()
	publicRouter.HandleFunc("/register", ac.RegisterHandler()).Methods("POST")
	publicRouter.HandleFunc("/login", ac.LoginHandler()).Methods("POST")
	publicRouter.HandleFunc("/verify/{token}", func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&GorillaParamExtractor{Vars: mux.Vars(r)}).ServeHTTP(w, r)
	}).Methods("GET")

	if ac.CanLoginWithOAuth() {
		publicRouter.HandleFunc("/oauth", func(w http.ResponseWriter, r *http.Request) {
			gothic.BeginAuthHandler(w, r)
		}).Methods("GET")
		publicRouter.HandleFunc("/oauth/callback", ac.OAuthCallbackHandler()).Methods("GET")
	}

	publicRouter.HandleFunc("/magic-link", ac.SendMagicLinkHandler()).Methods("POST")
	publicRouter.HandleFunc("/magic-link/{token}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ac.CompleteMagicLinkSignInHandler(&GorillaParamExtractor{Vars: vars}).ServeHTTP(w, r)
	}).Methods("GET")

	publicRouter.HandleFunc("/reset-password", ac.SendPasswordResetLinkHandler()).Methods("POST")
	publicRouter.HandleFunc("/reset-password/{token}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ac.CompletePasswordResetHandler(&GorillaParamExtractor{Vars: vars}).ServeHTTP(w, r)
	}).Methods("PUT")

	protectedRouter := r.PathPrefix("/auth").Subrouter()
	protectedRouter.Use(ac.AuthMiddleware())
	protectedRouter.HandleFunc("/me", ac.GetMeHandler()).Methods("GET")
	protectedRouter.HandleFunc("/logout", ac.LogoutHandler()).Methods("POST")
}
