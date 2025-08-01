package chi_adapter

import (
	"net/http"

	"github.com/AdrianTworek/go-auth/core"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth/gothic"
)

type ChiParamExtractor struct {
	Req *http.Request
}

func (c *ChiParamExtractor) GetParam(key string) string {
	return chi.URLParam(c.Req, key)
}

func InitAuth(ac *core.AuthClient, r *chi.Mux) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", ac.RegisterHandler())
		r.Post("/login", ac.LoginHandler())
		r.Get("/verify/{token}", func(w http.ResponseWriter, r *http.Request) {
			ac.VerifyEmailHandler(&ChiParamExtractor{Req: r})(w, r)
		})

		if ac.CanLoginWithOAuth() {
			r.Get("/oauth", gothic.BeginAuthHandler)
			r.Get("/oauth/callback", ac.OAuthCallbackHandler())
		}

		r.Route("/magic-link", func(r chi.Router) {
			r.Post("/", ac.SendMagicLinkHandler())
			r.Get("/{token}", func(w http.ResponseWriter, r *http.Request) {
				ac.CompleteMagicLinkSignInHandler(&ChiParamExtractor{Req: r})(w, r)
			})
		})

		r.Route("/reset-password", func(r chi.Router) {
			r.Post("/", ac.SendPasswordResetLinkHandler())
			r.Put("/{token}", func(w http.ResponseWriter, r *http.Request) {
				ac.CompletePasswordResetHandler(&ChiParamExtractor{Req: r})(w, r)
			})
		})

		r.Group(func(r chi.Router) {
			r.Use(ac.AuthMiddleware())
			r.Get("/me", ac.GetMeHandler())
			r.Post("/logout", ac.LogoutHandler())
		})
	})
}
