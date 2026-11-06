package core

import (
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

// Env holds all the environment variables needed for the application. This struct should be only used in test environments.
// In library code all environmental variables should be passed as params to config like SessionSecret or DSN in database config.
type Env struct {
	BaseURL            string
	Port               int
	SessionSecret      string
	DSN                string
	GoogleClientSecret string
	GoogleClientID     string
	GithubClientSecret string
	GithubClientID     string
}

// Setup Env object with default values and read from .env file, this should be only used in test environments
func NewEnv(isTest bool) (*Env, error) {
	_, b, _, _ := runtime.Caller(0)
	configPath := filepath.Join(filepath.Dir(b), "..", ".env")
	if isTest {
		configPath = filepath.Join(filepath.Dir(b), "..", ".test.env")
	}
	viper.SetConfigFile(configPath)
	viper.SetDefault("BASE_URL", "http://localhost:8080")
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("SESSION_SECRET", "change-me")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	return &Env{
		BaseURL:            viper.GetString("BASE_URL"),
		Port:               viper.GetInt("PORT"),
		SessionSecret:      viper.GetString("SESSION_SECRET"),
		DSN:                viper.GetString("DSN"),
		GoogleClientSecret: viper.GetString("GOOGLE_CLIENT_SECRET"),
		GoogleClientID:     viper.GetString("GOOGLE_CLIENT_ID"),
		GithubClientSecret: viper.GetString("GITHUB_CLIENT_SECRET"),
		GithubClientID:     viper.GetString("GITHUB_CLIENT_ID"),
	}, nil
}
