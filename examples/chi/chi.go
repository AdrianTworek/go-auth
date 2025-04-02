package main

import (
	"fmt"
	"log"
	"net/http"

	chi_adapter "github.com/AdrianTworek/go-auth/adapters/chi"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: core.DatabaseConfig{
			Dsn: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		},
	})
	if err != nil {
		log.Fatalf("Error creating auth client: %v", err)
	}

	chi_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	http.ListenAndServe(":8080", r)
}
