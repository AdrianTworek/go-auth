package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- helpers ---------------------------------------------------------------

// auditRecorder captures the events delivered to a hook so a test can assert on what
// the library emitted. Events are copied on capture because handlers reuse the event
// and its AuditInfo, so holding the pointers would let later writes leak backwards.
type auditRecorder struct {
	mu     sync.Mutex
	events []AuthEvent
}

func (ar *auditRecorder) hook(_ context.Context, e *AuthEvent) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	captured := *e
	if e.Audit != nil {
		audit := *e.Audit
		captured.Audit = &audit
	}
	ar.events = append(ar.events, captured)
	return nil
}

func (ar *auditRecorder) allOf(eventType AuthEventType) []AuthEvent {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	var found []AuthEvent
	for _, e := range ar.events {
		if e.Type == eventType {
			found = append(found, e)
		}
	}
	return found
}

// only returns the single recorded event of the given type, failing unless exactly one
// was delivered — an event firing twice is as much a defect as it not firing at all.
func (ar *auditRecorder) only(t *testing.T, eventType AuthEventType) AuthEvent {
	t.Helper()
	found := ar.allOf(eventType)
	require.Len(t, found, 1, "expected exactly one %s event", eventType)
	return found[0]
}

// auditConfig returns a test config whose hooks record every listed event type.
func auditConfig(rec *auditRecorder, eventTypes ...AuthEventType) *AuthConfig {
	hooks := HookMap{}
	for _, eventType := range eventTypes {
		hooks[eventType] = HookList{rec.hook}
	}
	c := NewTestAuthConfig(nil, nil, nil)
	c.Hooks = &hooks
	return c
}

const auditNewPassword = "NewP@ssword123!"

func changePasswordBody(currentPassword string) map[string]string {
	return map[string]string{
		"currentPassword": currentPassword,
		"newPassword":     auditNewPassword,
		"confirmPassword": auditNewPassword,
	}
}

// --- password changed ------------------------------------------------------

func Test_Integration_AuditPasswordChanged(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventPasswordChanged))
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie,
		changePasswordBody(TestUserData[DefaultUser].Password))
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventPasswordChanged)
	require.NotNil(t, ev.User)
	assert.Equal(t, TestUserData[DefaultUser].Email, ev.User.Email)

	require.NotNil(t, ev.Audit)
	assert.Equal(t, string(EventPasswordChanged), ev.Audit.Action)
	assert.Equal(t, AuditTargetUser, ev.Audit.TargetType)
	assert.Equal(t, userID(t, db, TestUserData[DefaultUser].Email), ev.Audit.TargetID)
	assert.Equal(t, "192.0.2.1", ev.Audit.IP, "the httptest peer address, port stripped")
	assert.False(t, ev.Audit.OccurredAt.IsZero(), "the event should carry when it happened")
}

// --- email change ----------------------------------------------------------

func Test_Integration_AuditEmailChangeRequested(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventEmailChangeRequested))
	defer CleanupIntegration(t, dbCtr, db)

	newEmail := "audit-requested@example.com"
	app.mailer.On("SendEmailChangeEmail", newEmail, mock.Anything).Return(nil)
	app.mailer.On("SendEmailChangeNotification", TestUserData[DefaultUser].Email, newEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        newEmail,
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventEmailChangeRequested)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetEmail, ev.Audit.TargetType)
	assert.Equal(t, newEmail, ev.Audit.TargetID, "the event is about the pending address")
	require.NotNil(t, ev.User)
	assert.Equal(t, TestUserData[DefaultUser].Email, ev.User.Email,
		"the actor still holds the old address while the change is pending")
}

func Test_Integration_AuditEmailChangeConfirmed(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventEmailChangeConfirmed))
	defer CleanupIntegration(t, dbCtr, db)

	oldEmail := TestUserData[DefaultUser].Email
	newEmail := "audit-confirmed@example.com"
	app.mailer.On("SendEmailChangeEmail", newEmail, mock.Anything).Return(nil)
	app.mailer.On("SendEmailChangeNotification", oldEmail, newEmail, mock.Anything).Return(nil)
	app.mailer.On("SendEmailChangeCompletedNotification", oldEmail, newEmail).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        newEmail,
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	require.Equal(t, http.StatusOK, rr.Code)

	token := mailToken(t, app, "SendEmailChangeEmail")
	confirmRR := doGet(t, app, strings.Replace(PathConfirmEmailChange, "{token}", token, 1), nil)
	require.Equal(t, http.StatusOK, confirmRR.Code)

	ev := rec.only(t, EventEmailChangeConfirmed)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetEmail, ev.Audit.TargetType)
	assert.Equal(t, newEmail, ev.Audit.TargetID)
	require.NotNil(t, ev.User)
	assert.Equal(t, newEmail, ev.User.Email, "the account already holds the new address")
}

func Test_Integration_AuditEmailChangeCancelled(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventEmailChangeCancelled))
	defer CleanupIntegration(t, dbCtr, db)

	oldEmail := TestUserData[DefaultUser].Email
	newEmail := "audit-cancelled@example.com"
	app.mailer.On("SendEmailChangeEmail", newEmail, mock.Anything).Return(nil)
	app.mailer.On("SendEmailChangeNotification", oldEmail, newEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        newEmail,
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	require.Equal(t, http.StatusOK, rr.Code)

	// The cancel link carries the same single-use token as the confirmation link.
	token := mailToken(t, app, "SendEmailChangeEmail")
	cancelPath := strings.Replace(PathCancelEmailChange, "{token}", token, 1)
	cancelRR := doGet(t, app, cancelPath, nil)
	require.Equal(t, http.StatusOK, cancelRR.Code)

	ev := rec.only(t, EventEmailChangeCancelled)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetEmail, ev.Audit.TargetType)
	assert.Equal(t, newEmail, ev.Audit.TargetID, "the event names the abandoned address")
	require.NotNil(t, ev.User, "the token identifies the account, even though the endpoint is public")
	assert.Equal(t, oldEmail, ev.User.Email, "the account keeps its original address")
}

// --- session revocation ----------------------------------------------------

func Test_Integration_AuditSessionRevoked(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventSessionRevoked))
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	other := sessionCookieFor(t, app, uid)
	otherID := sessionIDByToken(t, db, other.Value)

	rr := doDelete(t, app, PathSessions+"/"+otherID, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventSessionRevoked)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetSession, ev.Audit.TargetType)
	assert.Equal(t, otherID, ev.Audit.TargetID, "the event names which session was revoked")
	require.NotNil(t, ev.User)
	assert.Equal(t, uid, ev.User.ID)
}

func Test_Integration_AuditSessionRevokedNotFiredForUnknownSession(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventSessionRevoked))
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doDelete(t, app, PathSessions+"/00000000-0000-0000-0000-000000000000", cookie)
	require.Equal(t, http.StatusNotFound, rr.Code)

	assert.Empty(t, rec.allOf(EventSessionRevoked), "nothing was revoked, so nothing to audit")
}

func Test_Integration_AuditAllOtherSessionsRevoked(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventAllOtherSessionsRevoked))
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	sessionCookieFor(t, app, uid) // a second device to revoke

	rr := doDelete(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventAllOtherSessionsRevoked)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetUser, ev.Audit.TargetType)
	assert.Equal(t, uid, ev.Audit.TargetID)
}

// --- failed login ----------------------------------------------------------

// The failed-login event distinguishes why a login failed while the HTTP response stays
// uniform: the anti-enumeration guarantee is about what the *response* reveals, not what
// a consumer may observe in its own process.
func Test_Integration_AuditLoginFailedReasonsStayOutOfTheResponse(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventLoginFailed))
	defer CleanupIntegration(t, dbCtr, db)

	unknown := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    "nobody@example.com",
		"password": "whatever-123",
	})
	badPassword := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[DefaultUser].Email,
		"password": "definitely-not-the-password",
	})

	require.Equal(t, http.StatusUnauthorized, unknown.Code)
	assert.Equal(t, unknown.Code, badPassword.Code, "both failures must share a status")
	assert.Equal(t, unknown.Body.String(), badPassword.Body.String(),
		"both failures must be byte-identical, or the response enumerates accounts")

	events := rec.allOf(EventLoginFailed)
	require.Len(t, events, 2)

	require.NotNil(t, events[0].Audit)
	assert.Equal(t, LoginFailureUnknownAccount, events[0].Audit.Reason)
	assert.Equal(t, AuditTargetEmail, events[0].Audit.TargetType)
	assert.Equal(t, "nobody@example.com", events[0].Audit.TargetID)
	assert.Nil(t, events[0].User, "there is no account to attach when it doesn't exist")

	require.NotNil(t, events[1].Audit)
	assert.Equal(t, LoginFailureBadPassword, events[1].Audit.Reason)
	assert.Equal(t, TestUserData[DefaultUser].Email, events[1].Audit.TargetID)
	require.NotNil(t, events[1].User, "the account exists, so the event identifies it")
	assert.Equal(t, TestUserData[DefaultUser].Email, events[1].User.Email)
}

func Test_Integration_AuditLoginFailedUnverifiedEmail(t *testing.T) {
	rec := &auditRecorder{}
	c := auditConfig(rec, EventLoginFailed)
	c.Session.RequireVerifiedEmail = true
	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[UnverifiedUser].Email,
		"password": TestUserData[UnverifiedUser].Password,
	})
	require.Equal(t, http.StatusForbidden, rr.Code)

	ev := rec.only(t, EventLoginFailed)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, LoginFailureUnverifiedEmail, ev.Audit.Reason)
	require.NotNil(t, ev.User)
	assert.False(t, ev.User.EmailVerified)
}

func Test_Integration_AuditLoginFailedNotFiredOnSuccess(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventLoginFailed))
	defer CleanupIntegration(t, dbCtr, db)

	rr := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[DefaultUser].Email,
		"password": TestUserData[DefaultUser].Password,
	})
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Empty(t, rec.allOf(EventLoginFailed))
}

// --- post-commit semantics -------------------------------------------------

// A failing audit handler must not fail the request: the action it describes is already
// durable, so a 500 here would report a rollback that never happened.
func Test_Integration_AuditHookErrorDoesNotFailRequest(t *testing.T) {
	hooks := HookMap{
		EventPasswordChanged: HookList{
			func(context.Context, *AuthEvent) error { return errors.New("audit sink is down") },
		},
	}
	c := NewTestAuthConfig(nil, nil, nil)
	c.Hooks = &hooks

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie,
		changePasswordBody(TestUserData[DefaultUser].Password))
	require.Equal(t, http.StatusOK, rr.Code, "a broken audit handler must not break the request")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, TestUserData[DefaultUser].Email)
	require.NoError(t, err)
	assert.True(t, dbUser.Password.Compare(auditNewPassword), "the change must still be durable")
}

// A handler observes state that is already committed — proven by reading the new
// password through a separate connection from inside the handler, which would still see
// the old value if the event fired inside the transaction.
func Test_Integration_AuditEventFiresAfterCommit(t *testing.T) {
	var app *TestApp
	var committed bool

	hooks := HookMap{
		EventPasswordChanged: HookList{
			func(ctx context.Context, _ *AuthEvent) error {
				user, err := app.storage.User.GetByEmail(ctx, nil, TestUserData[DefaultUser].Email)
				if err != nil {
					return err
				}
				committed = user.Password.Compare(auditNewPassword)
				return nil
			},
		},
	}
	c := NewTestAuthConfig(nil, nil, nil)
	c.Hooks = &hooks

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie,
		changePasswordBody(TestUserData[DefaultUser].Password))
	require.Equal(t, http.StatusOK, rr.Code)

	assert.True(t, committed, "the handler must observe the committed password change")
}

// A handler may still short-circuit the response with a sentinel; what it cannot do is
// undo the action.
func Test_Integration_AuditHookSentinelStillShapesResponse(t *testing.T) {
	hooks := HookMap{
		EventPasswordChanged: HookList{
			func(context.Context, *AuthEvent) error {
				return NewHookResponse(http.StatusTeapot, map[string]any{"audited": true})
			},
		},
	}
	c := NewTestAuthConfig(nil, nil, nil)
	c.Hooks = &hooks

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie,
		changePasswordBody(TestUserData[DefaultUser].Password))
	require.Equal(t, http.StatusTeapot, rr.Code)
	assert.Contains(t, rr.Body.String(), "audited")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, TestUserData[DefaultUser].Email)
	require.NoError(t, err)
	assert.True(t, dbUser.Password.Compare(auditNewPassword),
		"the sentinel shapes the response but cannot roll the change back")
}

// --- client address --------------------------------------------------------

func Test_Integration_AuditEventCarriesForwardedClientIP(t *testing.T) {
	rec := &auditRecorder{}
	c := auditConfig(rec, EventPasswordChanged)
	c.TrustedProxy = &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 1}

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	body, err := json.Marshal(changePasswordBody(TestUserData[DefaultUser].Password))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, PathChangePassword, bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventPasswordChanged)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, "203.0.113.7", ev.Audit.IP, "the real client, not the proxy")
}

func Test_Integration_AuditEventIgnoresForwardedHeaderWhenProxyUntrusted(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventPasswordChanged))
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	body, err := json.Marshal(changePasswordBody(TestUserData[DefaultUser].Password))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, PathChangePassword, bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	ev := rec.only(t, EventPasswordChanged)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, "192.0.2.1", ev.Audit.IP,
		"a client must not be able to choose what lands in its own audit record")
}
