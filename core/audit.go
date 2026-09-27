package core

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// newAuditEvent builds one of the account-security audit events, filling in the
// request-derived detail — resolved client IP, user agent, timestamp — so every call
// site records it the same way. Callers supply only what is specific to the action:
// the target and, for a failed login, the reason.
func (ac *AuthClient) newAuditEvent(
	eventType AuthEventType,
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	audit AuditInfo,
) *AuthEvent {
	audit.IP = ac.clientIP(r)
	audit.UserAgent = r.UserAgent()
	audit.OccurredAt = time.Now().UTC()

	// Normalise email targets centrally so the call sites can't disagree on casing: a
	// consumer keying its records on the address would otherwise see one account under
	// two spellings.
	if audit.TargetType == AuditTargetEmail {
		audit.TargetID = normalizeEmail(audit.TargetID)
	}

	event := NewAuthEvent(eventType, w, r, user)
	event.Audit = &audit
	return event
}

// triggerAudit fires a post-commit audit event and reports whether the caller should
// carry on and write its own response.
//
// The action these events describe is already durable, so a handler error cannot undo
// it: failing the request would tell the caller their password change or session
// revocation did not happen when it did. The error is logged loudly and the request
// continues — the same fail-open reasoning already applied to the rate limiter and to
// the best-effort notification mails.
//
// The Hook* sentinels are deliberately not special-cased: a handler may still
// short-circuit with HookError, HookResponse or HookRedirect, in which case the response
// has been written and this reports false. What a handler cannot do is roll the action
// back.
//
// Trigger stops at the first handler that fails, so a broken subscriber also suppresses
// any registered after it for the same event. That is the dispatcher's existing
// behaviour, kept deliberately rather than special-cased here.
func (ac *AuthClient) triggerAudit(ctx context.Context, event *AuthEvent) bool {
	cont, err := ac.hookStore.Trigger(ctx, event)
	if err != nil {
		slog.Error(
			"audit hook failed; the action it describes is already committed",
			"type", event.Type,
			"error", err,
		)
		return true
	}
	return cont
}

// auditLoginFailed emits EventLoginFailed for a rejected login attempt. The submitted
// address is recorded whether or not it names a real account — that is what makes the
// event usable for spotting enumeration — and user is nil when no account exists. The
// HTTP response the caller goes on to write stays uniform across every reason.
func (ac *AuthClient) auditLoginFailed(
	w http.ResponseWriter,
	r *http.Request,
	user *store.User,
	email string,
	reason string,
) bool {
	return ac.triggerAudit(r.Context(), ac.newAuditEvent(EventLoginFailed, w, r, user, AuditInfo{
		TargetType: AuditTargetEmail,
		TargetID:   email,
		Reason:     reason,
	}))
}
