package core

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/AdrianTworek/go-auth/core/internal/store"
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

func writeJSONError(w http.ResponseWriter, status int, message string) {
	type envelope struct {
		Error string `json:"error"`
	}

	if err := writeJSON(w, status, &envelope{Error: message}); err != nil {
		slog.Error("failed to write JSON error response", "error", err)
	}
}

func writeJSONResponse(w http.ResponseWriter, status int, data any) {
	type envelope struct {
		Data any `json:"data"`
	}

	if err := writeJSON(w, status, &envelope{Data: data}); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}

// serverError logs the underlying error with request context and returns a
// generic 500 to the client, so internal details (DB/driver errors, etc.) are
// never leaked in the response body.
func serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
}

// Context
type ctxKey string

const (
	ctxUserKey         = ctxKey("user")
	ctxSessionTokenKey = ctxKey("session_token")
)

func getUserFromContext(r *http.Request) (*store.User, bool) {
	user, ok := r.Context().Value(ctxUserKey).(*store.User)
	return user, ok
}

func getSessionTokenFromContext(r *http.Request) (string, bool) {
	token, ok := r.Context().Value(ctxSessionTokenKey).(string)
	return token, ok
}
