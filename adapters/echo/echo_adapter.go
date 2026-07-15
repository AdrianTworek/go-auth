package echo_adapter

import (
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type EchoParamExtractor struct {
	Ctx echo.Context
}

func (e *EchoParamExtractor) GetParam(key string) string {
	return e.Ctx.Param(key)
}

func InitAuth(ac *core.AuthClient, e *echo.Echo) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}
	// Protected handlers are pre-wrapped with the auth middleware, so echo needs no
	// WrapMiddleware call.
	mw := ac.AuthMiddleware()

	e.POST(core.PathRegister, echo.WrapHandler(ac.RegisterHandler()))
	e.POST(core.PathLogin, echo.WrapHandler(ac.LoginHandler()))
	e.GET(core.ColonParamPattern(core.PathVerifyEmail), func(c echo.Context) error {
		return echo.WrapHandler(ac.VerifyEmailHandler(&EchoParamExtractor{Ctx: c}))(c)
	})
	e.POST(core.PathResendVerification, echo.WrapHandler(ac.ResendVerificationHandler()))
	e.GET(core.ColonParamPattern(core.PathConfirmEmailChange), func(c echo.Context) error {
		return echo.WrapHandler(ac.ConfirmEmailChangeHandler(&EchoParamExtractor{Ctx: c}))(c)
	})

	if ac.CanLoginWithOAuth() {
		e.GET(core.PathOAuthBegin, func(c echo.Context) error {
			gothic.BeginAuthHandler(c.Response(), c.Request())
			return nil
		})
		e.GET(core.PathOAuthCallback, echo.WrapHandler(ac.OAuthCallbackHandler()))
	}

	if ac.CanLoginWithMagicLink() {
		e.POST(core.PathSendMagicLink, echo.WrapHandler(ac.SendMagicLinkHandler()))
		e.GET(core.ColonParamPattern(core.PathMagicLink), func(c echo.Context) error {
			return echo.WrapHandler(ac.CompleteMagicLinkSignInHandler(&EchoParamExtractor{Ctx: c}))(c)
		})
	}

	e.POST(core.PathSendPasswordReset, echo.WrapHandler(ac.SendPasswordResetLinkHandler()))
	e.PUT(core.ColonParamPattern(core.PathPasswordReset), func(c echo.Context) error {
		return echo.WrapHandler(ac.CompletePasswordResetHandler(&EchoParamExtractor{Ctx: c}))(c)
	})

	e.GET(core.PathMe, echo.WrapHandler(mw(ac.GetMeHandler())))
	e.POST(core.PathLogout, echo.WrapHandler(mw(ac.LogoutHandler())))
	e.POST(core.PathChangePassword, echo.WrapHandler(mw(ac.ChangePasswordHandler())))
	e.POST(core.PathChangeEmail, echo.WrapHandler(mw(ac.ChangeEmailHandler())))
}
