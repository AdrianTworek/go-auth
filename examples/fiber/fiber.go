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
	})
	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	fiber_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	r.Listen(":8080")
}
