package core

import (
	"encoding/json"
	"net/http"

	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/go-playground/validator/v10"
)

// JSON
var Validate *validator.Validate

func init() {
	Validate = validator.New(validator.WithRequiredStructEnabled())
}

func writeJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func readAndValidateJSON(w http.ResponseWriter, r *http.Request, data any) error {
	if err := readJSON(w, r, data); err != nil {
		return err
	}

	if err := Validate.Struct(data); err != nil {
		return err
	}

	return nil
}

func readJSON(w http.ResponseWriter, r *http.Request, data any) error {
	maxBytes := 1_048_576 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	return decoder.Decode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) error {
	type envelope struct {
		Error string `json:"error"`
	}

	return writeJSON(w, status, &envelope{Error: message})
}

func writeJSONResponse(w http.ResponseWriter, status int, data any) error {
	type envelope struct {
		Data any `json:"data"`
	}

	return writeJSON(w, status, &envelope{Data: data})
}

// Context
type ctxKey string

const ctxUserKey = ctxKey("user")

func getUserFromContext(r *http.Request) *store.User {
	return r.Context().Value(ctxUserKey).(*store.User)
}
