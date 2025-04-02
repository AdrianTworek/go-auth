package gin_adapter

import (
	"github.com/AdrianTworek/go-auth/core"
	"github.com/gin-gonic/gin"
	adapter "github.com/gwatts/gin-adapter"
)

type GinParamExtractor struct {
	Ctx *gin.Context
}

func (g *GinParamExtractor) GetParam(key string) string {
	return g.Ctx.Param(key)
}

func InitAuth(ac *core.AuthClient, r *gin.Engine) {
	publicRouter := r.Group("/auth")
	publicRouter.POST("/register", gin.WrapH(ac.RegisterHandler()))
	publicRouter.POST("/login", gin.WrapH(ac.LoginHandler()))
	publicRouter.PUT("/verify/:token", (func(c *gin.Context) {
		ac.VerifyEmailHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	}))

	publicMagicLinkRouter := publicRouter.Group("/magic-link")
	publicMagicLinkRouter.POST("/", gin.WrapH(ac.SendMagicLinkHandler()))
	publicMagicLinkRouter.GET("/:token", func(c *gin.Context) {
		ac.CompleteMagicLinkSignInHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	})

	publicResetPasswordRouter := publicRouter.Group("/reset-password")
	publicResetPasswordRouter.POST("/", gin.WrapH(ac.SendPasswordResetLinkHandler()))
	publicResetPasswordRouter.GET("/:token", func(c *gin.Context) {
		ac.CompletePasswordResetHandler(&GinParamExtractor{Ctx: c})(c.Writer, c.Request)
	})

	protectedRouter := r.Group("/auth")
	protectedRouter.Use(adapter.Wrap(ac.AuthMiddleware()))
	protectedRouter.GET("/me", gin.WrapH(ac.GetMeHandler()))
	protectedRouter.POST("/logout", gin.WrapH(ac.LogoutHandler()))
}
