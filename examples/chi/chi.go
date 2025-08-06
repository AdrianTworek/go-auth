package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/AdrianTworek/go-auth/adapters/chi"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/AdrianTworek/go-auth/examples"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"
)

func init() {
	examples.SetupEnv()
}

func beforeLogin(ctx context.Context, event *core.AuthEvent) error {
	slog.Info("User logged in this is from the after login hook", "event", event)
	return nil
}

func afterLogin(ctx context.Context, event *core.AuthEvent) error {
	return &core.HookRedirect{
		URL:    "http://localhost:8080/front/success",
		Status: http.StatusFound,
	}
}

func emailVerfificationFailed(ctx context.Context, event *core.AuthEvent) error {
	slog.Info("email verification failed")
}

func main() {
	r := chi.NewRouter()

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
					"email",
					"profile",
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
				emailVerfificationFailed,
			},
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
				<h1>Login Failed</h1>
			</body>
		</html>
		`
		w.Write([]byte(html))
	})
	chi_adapter.InitAuth(ac, r)

	fmt.Println("🚀 Listening on port :8080")
	http.ListenAndServe(":8080", r)
}
