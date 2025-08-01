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
		Session: core.SessionConfig{
			MagicLinkSuccesfulRedirectURL: "http://localhost:8080/front/success",
			MagicLinkFailedRedirectURL:    "http://localhost:8080/front/failed",
			LoginAfterRegister:            true,
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
	http.ListenAndServe(":8080", r)
}
