package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"

	gin_adapter "github.com/AdrianTworek/go-auth/adapters/gin"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/AdrianTworek/go-auth/examples"
)

func init() {
	examples.SetupEnv()
}

func beforeLogin(ctx context.Context, event *core.AuthEvent) error {
	slog.Info("this is from the before login hook", "event", event)
	return nil
}

func afterLogin(ctx context.Context, event *core.AuthEvent) error {
	slog.Info("this is from the after login hook", "event", event)
	return &core.HookRedirect{
		URL:    "http://localhost:8080/front/success",
		Status: http.StatusFound,
	}
}

func emailVerificationFailed(ctx context.Context, event *core.AuthEvent) error {
	slog.Info("email verification failed")
	return &core.HookRedirect{
		URL:    "http://localhost:8080/front/failed",
		Status: http.StatusFound,
	}
}

func main() {
	r := gin.Default()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: &core.DatabaseConfig{
			Dsn: viper.GetString("DSN"),
		},
		Session: &core.SessionConfig{
			MagicLinkSuccessfulRedirectURL: "http://localhost:8080/front/success",
			MagicLinkFailedRedirectURL:     "http://localhost:8080/front/failed",
			LoginAfterRegister:             true,
			// This example runs over plain HTTP, so disable Secure to let the
			// browser send the session cookie. Remove this in production (HTTPS).
			CookieSecure: core.Ptr(false),
		},
		OAuth: &core.OAuthConfig{
			Providers: []goth.Provider{
				google.New(
					viper.GetString("GOOGLE_CLIENT_ID"),
					viper.GetString("GOOGLE_CLIENT_SECRET"),
					fmt.Sprintf(
						"%s/auth/oauth/callback?provider=google",
						viper.GetString("BASE_URL"),
					),
					"email",
					"profile",
				),
				github.New(
					viper.GetString("GITHUB_CLIENT_ID"),
					viper.GetString("GITHUB_CLIENT_SECRET"),
					fmt.Sprintf(
						"%s/auth/oauth/callback?provider=github",
						viper.GetString("BASE_URL"),
					),
					"user:email",
				),
			},
		},
		SessionSecret: viper.GetString("SESSION_SECRET"),
		BaseURL:       "http://localhost:8080",
		Hooks: &core.HookMap{
			core.EventBeforeLogin: core.HookList{
				beforeLogin,
			},
			core.EventAfterLogin: core.HookList{
				afterLogin,
			},
			core.EventEmailVerificationFailed: core.HookList{
				emailVerificationFailed,
			},
		},
	})
	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	r.GET("/front/success", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		html := `
		<!DOCTYPE html>
		<html>
			<head>
				<title>My HTML Page</title>
			</head>
			<body>
				<h1>Logged in successfully</h1>
			</body>
		</html>
		`
		c.String(http.StatusOK, html)
	})

	r.GET("/front/failed", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		html := `
		<!DOCTYPE html>
		<html>
			<head>
				<title>My HTML Page</title>
			</head>
			<body>
				<h1>Login Failed</h1>
			</body>
		</html>
		`
		c.String(http.StatusOK, html)
	})

	gin_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
