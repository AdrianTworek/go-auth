package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"

	fiber_adapter "github.com/AdrianTworek/go-auth/adapters/fiber"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/AdrianTworek/go-auth/examples"
)

func init() {
	examples.SetupEnv()
}

func main() {
	r := fiber.New()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: &core.DatabaseConfig{
			Dsn: viper.GetString("DSN"),
		},
		Session: &core.SessionConfig{
			MagicLinkSuccesfulRedirectURL: "http://localhost:8080/front/success",
			MagicLinkFailedRedirectURL:    "http://localhost:8080/front/failed",
			LoginAfterRegister:            true,
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
	})
	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	r.Get("/front/success", func(c *fiber.Ctx) error {
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

		return c.SendString(html)
	})

	r.Get("/front/failed", func(c *fiber.Ctx) error {
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

		return c.SendString(html)
	})

	fiber_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	log.Fatal(r.Listen(":8080"))
}
