package main

import (
	"fmt"
	"log"
	"net/http"

	gin_adapter "github.com/AdrianTworek/go-auth/adapters/gin"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: core.DatabaseConfig{
			Dsn: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		},
	})
	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	gin_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	http.ListenAndServe(":8080", r)
}
