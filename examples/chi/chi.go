package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/AdrianTworek/go-auth/adapters/chi"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

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

	r.HandleFunc("/front/success", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
		w.Write([]byte(html))
	})

	r.HandleFunc("/front/failed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := `
		<!DOCTYPE html>
		<html>
			<head>
				<title>My HTML Page</title>
			</head>
			<body>
				<h1>Login failed</h1>
			</body>
		</html>
		`
		w.Write([]byte(html))
	})
	chi_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	http.ListenAndServe(":8080", r)
}
