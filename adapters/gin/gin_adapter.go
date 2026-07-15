package gin_adapter

import (
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type GinParamExtractor struct {
	Ctx *gin.Context
}

func (g *GinParamExtractor) GetParam(key string) string {
	return g.Ctx.Param(key)
}

func InitAuth(ac *core.AuthClient, r *gin.Engine) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}
	// Protected handlers are pre-wrapped with the auth middleware, so gin needs no
	// separate middleware adapter.
	mw := ac.AuthMiddleware()

	r.POST(core.PathRegister, gin.WrapH(ac.RegisterHandler()))
	r.POST(core.PathLogin, gin.WrapH(ac.LoginHandler()))
	r.GET(core.ColonParamPattern(core.PathVerifyEmail), func(c *gin.Context) {
		ac.VerifyEmailHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	})
	r.POST(core.PathResendVerification, gin.WrapH(ac.ResendVerificationHandler()))
	r.GET(core.ColonParamPattern(core.PathConfirmEmailChange), func(c *gin.Context) {
		ac.ConfirmEmailChangeHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	})

	if ac.CanLoginWithOAuth() {
		r.GET(core.PathOAuthBegin, gin.WrapF(gothic.BeginAuthHandler))
		r.GET(core.PathOAuthCallback, gin.WrapH(ac.OAuthCallbackHandler()))
	}

	if ac.CanLoginWithMagicLink() {
		r.POST(core.PathSendMagicLink, gin.WrapH(ac.SendMagicLinkHandler()))
		r.GET(core.ColonParamPattern(core.PathMagicLink), func(c *gin.Context) {
			ac.CompleteMagicLinkSignInHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
		})
	}

	r.POST(core.PathSendPasswordReset, gin.WrapH(ac.SendPasswordResetLinkHandler()))
	r.PUT(core.ColonParamPattern(core.PathPasswordReset), func(c *gin.Context) {
		ac.CompletePasswordResetHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	})

	r.GET(core.PathMe, gin.WrapH(mw(ac.GetMeHandler())))
	r.POST(core.PathLogout, gin.WrapH(mw(ac.LogoutHandler())))
	r.POST(core.PathChangePassword, gin.WrapH(mw(ac.ChangePasswordHandler())))
	r.POST(core.PathChangeEmail, gin.WrapH(mw(ac.ChangeEmailHandler())))
}
