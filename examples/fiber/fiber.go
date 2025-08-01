package main

import (
	"fmt"
	"log"

	fiber_adapter "github.com/AdrianTworek/go-auth/adapters/fiber"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/gofiber/fiber/v2"
)

func main() {
	r := fiber.New()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: core.DatabaseConfig{
			Dsn: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		},
		Session: core.SessionConfig{
			MagicLinkSuccesfulRedirectURL: "http://localhost:8080/front/success",
			MagicLinkFailedRedirectURL:    "http://localhost:8080/front/failed",
			LoginAfterRegister:            true,
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
	r.Listen(":8080")
}
