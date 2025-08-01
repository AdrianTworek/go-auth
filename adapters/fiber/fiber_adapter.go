package fiber_adapter

import (
	"github.com/AdrianTworek/go-auth/core"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/markbates/goth/gothic"
)

type FiberParamExtractor struct {
	Ctx *fiber.Ctx
}

func (f *FiberParamExtractor) GetParam(key string) string {
	return f.Ctx.Params(key)
}

func InitAuth(ac *core.AuthClient, r *fiber.App) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}

	publicRouter := r.Group("/auth")
	publicRouter.Post("/register", adaptor.HTTPHandlerFunc(ac.RegisterHandler()))
	publicRouter.Post("/login", adaptor.HTTPHandlerFunc(ac.LoginHandler()))
	publicRouter.Get("/verify/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.VerifyEmailHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	if ac.CanLoginWithOAuth() {
		publicRouter.Get("/oauth", adaptor.HTTPHandlerFunc(gothic.BeginAuthHandler))
		publicRouter.Get("/oauth/callback", adaptor.HTTPHandlerFunc(ac.OAuthCallbackHandler()))
	}

	publicMagicLinkRouter := publicRouter.Group("/magic-link")
	publicMagicLinkRouter.Post("/", adaptor.HTTPHandlerFunc(ac.SendMagicLinkHandler()))
	publicMagicLinkRouter.Get("/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CompleteMagicLinkSignInHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	publicResetPasswordRouter := publicRouter.Group("/reset-password")
	publicResetPasswordRouter.Post("/", adaptor.HTTPHandlerFunc(ac.SendPasswordResetLinkHandler()))
	publicResetPasswordRouter.Put("/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CompletePasswordResetHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	protectedRouter := r.Group("/auth")
	protectedRouter.Use(adaptor.HTTPMiddleware(ac.AuthMiddleware()))
	protectedRouter.Get("/me", adaptor.HTTPHandlerFunc(ac.GetMeHandler()))
	protectedRouter.Post("/logout", adaptor.HTTPHandlerFunc(ac.LogoutHandler()))

}
