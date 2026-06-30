package fiber_adapter

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type FiberParamExtractor struct {
	Ctx *fiber.Ctx
}

func (f *FiberParamExtractor) GetParam(key string) string {
	return f.Ctx.Params(key)
}

func InitAuth(ac *core.AuthClient, app *fiber.App) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}
	// Protected handlers are pre-wrapped with the auth middleware, so fiber needs no
	// HTTPMiddleware call.
	mw := ac.AuthMiddleware()

	app.Post(core.PathRegister, adaptor.HTTPHandlerFunc(ac.RegisterHandler()))
	app.Post(core.PathLogin, adaptor.HTTPHandlerFunc(ac.LoginHandler()))
	app.Get(core.ColonParamPattern(core.PathVerifyEmail), func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.VerifyEmailHandler(&FiberParamExtractor{Ctx: c}))(c)
	})
	app.Post(core.PathResendVerification, adaptor.HTTPHandlerFunc(ac.ResendVerificationHandler()))

	if ac.CanLoginWithOAuth() {
		app.Get(core.PathOAuthBegin, adaptor.HTTPHandlerFunc(gothic.BeginAuthHandler))
		app.Get(core.PathOAuthCallback, adaptor.HTTPHandlerFunc(ac.OAuthCallbackHandler()))
	}

	if ac.CanLoginWithMagicLink() {
		app.Post(core.PathSendMagicLink, adaptor.HTTPHandlerFunc(ac.SendMagicLinkHandler()))
		app.Get(core.ColonParamPattern(core.PathMagicLink), func(c *fiber.Ctx) error {
			return adaptor.HTTPHandlerFunc(ac.CompleteMagicLinkSignInHandler(&FiberParamExtractor{Ctx: c}))(c)
		})
	}

	app.Post(core.PathSendPasswordReset, adaptor.HTTPHandlerFunc(ac.SendPasswordResetLinkHandler()))
	app.Put(core.ColonParamPattern(core.PathPasswordReset), func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CompletePasswordResetHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

	app.Get(core.PathMe, adaptor.HTTPHandler(mw(ac.GetMeHandler())))
	app.Post(core.PathLogout, adaptor.HTTPHandler(mw(ac.LogoutHandler())))
}
