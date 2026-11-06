package fiber_adapter

import (
	"context"
	"net/http"

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
	app.Get(core.ColonParamPattern(core.PathConfirmEmailChange), func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.ConfirmEmailChangeHandler(&FiberParamExtractor{Ctx: c}))(c)
	})
	app.Get(core.ColonParamPattern(core.PathCancelEmailChange), func(c *fiber.Ctx) error {
		return adaptor.HTTPHandlerFunc(ac.CancelEmailChangeHandler(&FiberParamExtractor{Ctx: c}))(c)
	})

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
	app.Post(core.PathChangePassword, adaptor.HTTPHandler(mw(ac.ChangePasswordHandler())))
	app.Post(core.PathChangeEmail, adaptor.HTTPHandler(mw(ac.ChangeEmailHandler())))

	app.Get(core.PathSessions, adaptor.HTTPHandler(mw(ac.ListSessionsHandler())))
	app.Delete(core.PathSessions, adaptor.HTTPHandler(mw(ac.RevokeOtherSessionsHandler())))
	app.Delete(core.ColonParamPattern(core.PathSession), adaptor.HTTPHandler(mw(ac.RevokeSessionHandler())))

	app.Get(core.PathAccounts, adaptor.HTTPHandler(mw(ac.ListAccountsHandler())))
	app.Delete(core.ColonParamPattern(core.PathAccount), adaptor.HTTPHandler(mw(ac.UnlinkAccountHandler())))

	if ac.CanUseMFA() {
		app.Post(core.PathMFATOTPSetup, adaptor.HTTPHandler(mw(ac.BeginTOTPEnrolmentHandler())))
		app.Post(core.PathMFATOTPConfirm, adaptor.HTTPHandler(mw(ac.TOTPEnrolmentConfirmHandler())))
		app.Post(core.PathMFATOTPDisable, adaptor.HTTPHandler(mw(ac.DisableTOTPHandler())))
		app.Post(core.PathMFABackupCodes, adaptor.HTTPHandler(mw(ac.RegenerateBackupCodesHandler())))
		app.Get(core.PathMFAStatus, adaptor.HTTPHandler(mw(ac.MFAStatusHandler())))
		app.Post(core.PathMFAVerify, adaptor.HTTPHandlerFunc(ac.MFAVerifyHandler()))
	}
}

// Middleware protects your own fiber routes with the library's session check. A request
// without a valid session gets a 401 and never reaches the route; one with a session
// reaches it with the user available from core.UserFromContext(c.UserContext()).
//
// fiber is not net/http, so the request the middleware authenticates is a converted
// copy. adaptor.HTTPMiddleware would copy its context values into fasthttp user values,
// but those are looked up by string key and the library's key is typed, so instead the
// authenticated context is layered over fiber's user context here.
func Middleware(ac *core.AuthClient) fiber.Handler {
	mw := ac.AuthMiddleware()
	return func(c *fiber.Ctx) error {
		var authed context.Context
		h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			authed = r.Context()
		}))
		if err := adaptor.HTTPHandler(h)(c); err != nil {
			return err
		}
		if authed == nil {
			// The middleware rejected the request and has written the 401.
			return nil
		}
		c.SetUserContext(layeredContext{Context: c.UserContext(), values: authed})
		return c.Next()
	}
}

// layeredContext keeps the deadline and cancellation of the request's own context while
// resolving values from the authenticated one first.
type layeredContext struct {
	context.Context
	values context.Context
}

func (l layeredContext) Value(key any) any {
	if v := l.values.Value(key); v != nil {
		return v
	}
	return l.Context.Value(key)
}
