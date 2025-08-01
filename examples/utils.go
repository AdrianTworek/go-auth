package examples

import (
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

func getEnvPath() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(b), "..", ".env")
}

func SetupEnv() {
	// This function can be used in all examples to ensure all variables are loaded and can be use using viper
	viper.SetConfigFile(getEnvPath())
	viper.SetDefault("BASE_URL", "http://localhost:8080")
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("SESSION_SECRET", "change-me")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	if err := viper.ReadInConfig(); err != nil {
		panic("Error reading .env file: " + err.Error())
	}
}
