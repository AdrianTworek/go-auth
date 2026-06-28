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

func InitAuth(ac *core.AuthClient, r *echo.Echo) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}

	publicRouter := r.Group("/auth")
	publicRouter.POST("/register", echo.WrapHandler(ac.RegisterHandler()))
	publicRouter.POST("/login", echo.WrapHandler(ac.LoginHandler()))
	publicRouter.GET("/verify/:token", func(c echo.Context) error {
		return echo.WrapHandler(ac.VerifyEmailHandler(&EchoParamExtractor{Ctx: c}))(c)
	})

	if ac.CanLoginWithOAuth() {
		publicRouter.GET("/oauth", func(c echo.Context) error {
			gothic.BeginAuthHandler(c.Response(), c.Request())
			return nil
		})
		publicRouter.GET("/oauth/callback", echo.WrapHandler(ac.OAuthCallbackHandler()))
	}

	if ac.CanLoginWithMagicLink() {
		publicRouter.POST("/magic-link", echo.WrapHandler(ac.SendMagicLinkHandler()))
		publicRouter.GET("/magic-link/:token", func(c echo.Context) error {
			return echo.WrapHandler(ac.CompleteMagicLinkSignInHandler(&EchoParamExtractor{Ctx: c}))(c)
		})
	}

	publicRouter.POST("/reset-password", echo.WrapHandler(ac.SendPasswordResetLinkHandler()))
	publicRouter.PUT("/reset-password/:token", func(c echo.Context) error {
		return echo.WrapHandler(ac.CompletePasswordResetHandler(&EchoParamExtractor{Ctx: c}))(c)
	})

	protectedRouter := r.Group("/auth")
	protectedRouter.Use(echo.WrapMiddleware(ac.AuthMiddleware()))
	protectedRouter.GET("/me", echo.WrapHandler(ac.GetMeHandler()))
	protectedRouter.POST("/logout", echo.WrapHandler(ac.LogoutHandler()))
}
