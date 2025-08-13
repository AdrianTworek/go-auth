package main

import (
	"fmt"
	"log"
	"net/http"

	echo_adapter "github.com/AdrianTworek/go-auth/adapters/echo"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/AdrianTworek/go-auth/examples"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"
)

func init() {
	examples.SetupEnv()
}

func main() {
	r := echo.New()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: &core.DatabaseConfig{
			Dsn: viper.GetString("DSN"),
		},
		Session: &core.SessionConfig{
			MagicLinkSuccesfulRedirectURL: "http://localhost:8080/front/success",
			MagicLinkFailedRedirectURL:    "http://localhost:8080/front/failed",
			LoginAfterRegister:            true,
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
	})

	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	r.GET("/front/success", func(c echo.Context) error {
		c.Set("Content-Type", "text/html; charset=utf-8")
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

		return c.HTML(http.StatusOK, html)
	})

	r.GET("/front/failed", func(c echo.Context) error {
		c.Set("Content-Type", "text/html; charset=utf-8")
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

		return c.HTML(http.StatusOK, html)
	})

	echo_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	r.Start(":8080")
}
