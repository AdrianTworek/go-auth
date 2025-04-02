package fiber_adapter

import (
	"github.com/AdrianTworek/go-auth/core"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

type FiberParamExtractor struct {
	Ctx *fiber.Ctx
}

func (f *FiberParamExtractor) GetParam(key string) string {
	return f.Ctx.Params(key)
}

func InitAuth(ac *core.AuthClient, r *fiber.App) {
	publicRouter := r.Group("/auth")
	publicRouter.Post("/register", adaptor.HTTPHandlerFunc(ac.RegisterHandler()))
	publicRouter.Post("/login", adaptor.HTTPHandlerFunc(ac.LoginHandler()))
	publicRouter.Put("/verify/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.VerifyEmailHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	publicMagicLinkRouter := publicRouter.Group("/magic-link")
	publicMagicLinkRouter.Post("/", adaptor.HTTPHandlerFunc(ac.SendMagicLinkHandler()))
	publicMagicLinkRouter.Get("/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CompleteMagicLinkSignInHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	publicResetPasswordRouter := publicRouter.Group("/reset-password")
	publicResetPasswordRouter.Post("/", adaptor.HTTPHandlerFunc(ac.SendPasswordResetLinkHandler()))
	publicResetPasswordRouter.Get("/:token", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CompletePasswordResetHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	protectedRouter := r.Group("/auth")
	protectedRouter.Use(adaptor.HTTPMiddleware(ac.AuthMiddleware()))
	protectedRouter.Get("/me", adaptor.HTTPHandlerFunc(ac.GetMeHandler()))
	protectedRouter.Post("/logout", adaptor.HTTPHandlerFunc(ac.LogoutHandler()))

}
