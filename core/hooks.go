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

	// The events below are the account-security audit events. Unlike the events above
	// they fire *after* their action has been committed, so a handler observes durable
	// state and an error it returns cannot roll the action back — see AuditInfo. Each
	// carries an AuditInfo on the event's Audit field.
	EventPasswordChanged         AuthEventType = "password_changed"
	EventEmailChangeRequested    AuthEventType = "email_change_requested"
	EventEmailChangeConfirmed    AuthEventType = "email_change_confirmed"
	EventEmailChangeCancelled    AuthEventType = "email_change_cancelled"
	EventSessionRevoked          AuthEventType = "session_revoked"
	EventAllOtherSessionsRevoked AuthEventType = "all_other_sessions_revoked"
	EventLoginFailed             AuthEventType = "login_failed"
)

// AuditTarget* name the kind of thing an audit event acted on, so a handler can read
// AuditInfo.TargetID without switching on the event type.
const (
	AuditTargetUser    = "user"
	AuditTargetSession = "session"
	AuditTargetEmail   = "email"
)

// LoginFailure* are the reasons carried by EventLoginFailed.
const (
	LoginFailureUnknownAccount  = "unknown_account"
	LoginFailureBadPassword     = "bad_password"
	LoginFailureUnverifiedEmail = "unverified_email"
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

// AuditInfo describes an account-security action, exposed to handlers for the audit
// events (EventPasswordChanged, the EventEmailChange* trio, EventSessionRevoked,
// EventAllOtherSessionsRevoked and EventLoginFailed).
//
// These events fire once the action has been committed. A handler therefore observes
// state that is already durable, and an error it returns is logged rather than failing
// the request: reporting a 500 would tell the caller their password change was rolled
// back when it was not. A handler may still short-circuit the response with the usual
// Hook* sentinels; what it cannot do is undo the action.
type AuditInfo struct {
	// Action is what happened, defaulting to the event type's string value.
	Action string
	// TargetType is the kind of thing acted on: AuditTargetUser, AuditTargetSession or
	// AuditTargetEmail.
	TargetType string
	// TargetID identifies the thing acted on, per TargetType: a user id, a session id,
	// or an email address.
	TargetID string
	// IP is the resolved client address, honouring TrustedProxy.
	IP string
	// UserAgent is the client's reported user agent.
	UserAgent string
	// OccurredAt is when the action happened, in UTC.
	OccurredAt time.Time
	// Reason is set only for EventLoginFailed: LoginFailureUnknownAccount,
	// LoginFailureBadPassword or LoginFailureUnverifiedEmail. It is deliberately more
	// specific than the HTTP response, which stays uniform across these cases so it
	// can't be used to enumerate accounts — the distinction is for the consumer's own
	// records, in-process. For the same reason a handler should do a similar amount of
	// work whatever the Reason: the responses are byte-identical, so a handler that is
	// markedly slower for one of them reintroduces a timing signal.
	Reason string
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
	// Audit is set only for the account-security audit events and describes what
	// happened. See AuditInfo.
	Audit *AuditInfo
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

// has reports whether any handler is registered for an event type, letting a caller
// skip work that is only needed to populate the event.
func (hs *HookStore) has(eventType AuthEventType) bool {
	return len(hs.hooks[eventType]) > 0
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
