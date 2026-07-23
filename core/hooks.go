package core

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

type AuthEventType string

const (
	EventBeforeLogin               AuthEventType = "before_login"
	EventAfterLogin                AuthEventType = "after_login"
	EventBeforeRegistration        AuthEventType = "before_registration"
	EventAfterRegistration         AuthEventType = "after_registration"
	EventLogout                    AuthEventType = "logout"
	EventOAuthCallback             AuthEventType = "oauth_callback"
	EventOAuthSuccess              AuthEventType = "oauth_success"
	EventPasswordResetSuccess      AuthEventType = "password_reset_success"
	EventPasswordResetInitialized  AuthEventType = "password_reset_initialized"
	EventEmailVerificationSuccess  AuthEventType = "email_verification_success"
	EventEmailVerificationCallback AuthEventType = "email_verification_callback"
	EventEmailVerificationFailed   AuthEventType = "email_verification_failed"
	// EventRateLimited fires when a request is throttled by the rate limiter, before
	// the 429 (or silent generic) response is written. The event's RateLimit field
	// carries the details. It is primarily observational (logging, metrics, alerting);
	// a hook may still respond early via the usual Hook* sentinels. Under an attack it
	// can fire frequently, so keep handlers cheap.
	EventRateLimited AuthEventType = "rate_limited"
)

// RateLimitInfo describes a throttling event, exposed to EventRateLimited hooks.
type RateLimitInfo struct {
	// Flow is the endpoint family that was limited, e.g. "login", "register",
	// "reset_password", "resend_verification", "magic_link", "change_password" or
	// "change_email".
	Flow string
	// Dimension is which limit tripped: "ip", "account" or "user".
	Dimension string
	// Key is the internal limiter key that was exceeded (contains the IP, email or
	// user id), useful for logging.
	Key string
	// RetryAfter is how long until the caller may retry. Zero for the silent
	// per-account cap on send endpoints.
	RetryAfter time.Duration
}

type AuthEvent struct {
	// Type of event that was triggered like EventBeforeLogin
	Type AuthEventType
	// User is optional some events won't include user
	User *store.User
	// Response writer from the request the event was sent from
	W http.ResponseWriter
	// Request object from the request the event was sent from
	R *http.Request
	// RateLimit is set only for EventRateLimited and describes the throttling event.
	RateLimit *RateLimitInfo
}

func NewAuthEvent(eventType AuthEventType, w http.ResponseWriter, r *http.Request, user *store.User) *AuthEvent {
	return &AuthEvent{
		Type: eventType,
		W:    w,
		R:    r,
		User: user,
	}
}

type HookFunc func(ctx context.Context, event *AuthEvent) error

type HookList = []HookFunc

type HookMap = map[AuthEventType]HookList

type HookStore struct {
	hooks HookMap
}

func NewHookStore(hooks HookMap) *HookStore {
	return &HookStore{
		hooks: hooks,
	}
}

// Trigger will trigger any hook that is set for that event type.
// Returns a flag if endpoint should continue and error if error occurred.
// If flag is true endpoint should continue if it is false it should return.
func (hs *HookStore) Trigger(ctx context.Context, event *AuthEvent) (bool, error) {
	hooks := hs.hooks[event.Type]
	if len(hooks) < 1 {
		slog.Info("skipping hook", "reason", "no handlers found", "type", event.Type)
		return true, nil
	}
	for _, hook := range hooks {

		err := hook(ctx, event)
		if err != nil {
			var hookErr *HookError
			if errors.As(err, &hookErr) {
				writeJSONError(event.W, hookErr.Status, hookErr.Message)
				return false, nil
			}
			var hookResponse *HookResponse
			if errors.As(err, &hookResponse) {
				writeJSONResponse(event.W, hookResponse.Status, hookResponse.Body)
				return false, nil
			}
			var hookRedirect *HookRedirect
			if errors.As(err, &hookRedirect) {
				http.Redirect(event.W, event.R, hookRedirect.URL, hookRedirect.Status)
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// HookError is used in hook functions to prematurely respond from endpoints with error message
type HookError struct {
	Message string
	Status  int
}

func (he *HookError) Error() string {
	return he.Message
}

func NewHookError(status int, m string) *HookError {
	return &HookError{
		Message: m,
		Status:  status,
	}
}

// HookResponse is used in hook functions to prematurely respond from endpoints with data
type HookResponse struct {
	Body   any
	Status int
}

func (hr *HookResponse) Error() string {
	return "not a real error: sentinel used to send an early response from an endpoint via a hook"
}

func NewHookResponse(status int, body any) *HookResponse {
	return &HookResponse{
		Body:   body,
		Status: status,
	}
}

// HookRedirect is used in hook functions to prematurely redirect from endpoints
type HookRedirect struct {
	URL    string
	Status int
}

func (hr *HookRedirect) Error() string {
	return "not a real error: sentinel used to redirect from an endpoint via a hook"
}

func NewHookRedirect(status int, url string) *HookRedirect {
	return &HookRedirect{
		URL:    url,
		Status: status,
	}
}
