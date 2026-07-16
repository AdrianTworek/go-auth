package core

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

// --- helpers ---------------------------------------------------------------

// sessionIDByToken resolves the id of the session backing a raw session token, by
// looking it up via the stored hash.
func sessionIDByToken(t *testing.T, db *sql.DB, rawToken string) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT id FROM sessions WHERE token = $1`, auth.HashToken(rawToken)).Scan(&id))
	return id
}

func doDelete(t *testing.T, app *TestApp, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

type sessionListResponse struct {
	Data struct {
		Sessions []struct {
			ID        string `json:"id"`
			IPAddress string `json:"ipAddress"`
			UserAgent string `json:"userAgent"`
			Current   bool   `json:"current"`
		} `json:"sessions"`
	} `json:"data"`
}

func decodeSessionList(t *testing.T, rr *httptest.ResponseRecorder) sessionListResponse {
	t.Helper()
	var resp sessionListResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

// --- list ------------------------------------------------------------------

func Test_Integration_ListSessions(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// A second device for the same user.
	uid := userID(t, db, TestUserData[DefaultUser].Email)
	other := sessionCookieFor(t, app, uid)

	rr := doGet(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	resp := decodeSessionList(t, rr)
	require.Len(t, resp.Data.Sessions, 2)

	// Exactly one session is flagged current, and it's the one behind this request.
	currentID := sessionIDByToken(t, db, cookie.Value)
	currentCount := 0
	for _, s := range resp.Data.Sessions {
		if s.Current {
			currentCount++
			assert.Equal(t, currentID, s.ID)
		}
	}
	assert.Equal(t, 1, currentCount)

	// The other device is present and not flagged current.
	otherID := sessionIDByToken(t, db, other.Value)
	found := false
	for _, s := range resp.Data.Sessions {
		if s.ID == otherID {
			found = true
			assert.False(t, s.Current)
		}
	}
	assert.True(t, found, "the second device's session should be listed")
}

func Test_Integration_ListSessionsRequiresAuth(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doGet(t, app, PathSessions, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- revoke others ---------------------------------------------------------

func Test_Integration_RevokeOtherSessions(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	other1 := sessionCookieFor(t, app, uid)
	other2 := sessionCookieFor(t, app, uid)

	rr := doDelete(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	// The current session still works; the other two are gone.
	_, err := app.storage.Session.Validate(t.Context(), nil, cookie.Value)
	assert.NoError(t, err)
	_, err = app.storage.Session.Validate(t.Context(), nil, other1.Value)
	assert.Error(t, err)
	_, err = app.storage.Session.Validate(t.Context(), nil, other2.Value)
	assert.Error(t, err)
}

func Test_Integration_RevokeOtherSessionsRequiresAuth(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doDelete(t, app, PathSessions, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- revoke one by id ------------------------------------------------------

func Test_Integration_RevokeSessionByID(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	other := sessionCookieFor(t, app, uid)
	otherID := sessionIDByToken(t, db, other.Value)

	rr := doDelete(t, app, strings.Replace(PathSession, "{id}", otherID, 1), cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	// The targeted session is revoked; the caller's own session is untouched, and no
	// logout cookie is issued (a different device was revoked).
	_, err := app.storage.Session.Validate(t.Context(), nil, other.Value)
	assert.Error(t, err)
	_, err = app.storage.Session.Validate(t.Context(), nil, cookie.Value)
	assert.NoError(t, err)
	assert.Nil(t, helper.GetSessionCookie(rr))
}

// Revoking the current session by id logs the caller out: the session is gone and the
// response clears the cookie.
func Test_Integration_RevokeCurrentSessionByIDClearsCookie(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)
	currentID := sessionIDByToken(t, db, cookie.Value)

	rr := doDelete(t, app, strings.Replace(PathSession, "{id}", currentID, 1), cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	_, err := app.storage.Session.Validate(t.Context(), nil, cookie.Value)
	assert.Error(t, err)

	cleared := helper.GetSessionCookie(rr)
	require.NotNil(t, cleared, "revoking the current session should clear the cookie")
	assert.Empty(t, cleared.Value)
}

// A user can't revoke another user's session: it's scoped to the caller, so an id that
// belongs to someone else is indistinguishable from a non-existent one (404).
func Test_Integration_RevokeSessionByIDOtherUserForbidden(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// A session owned by a different user.
	victimID := userID(t, db, TestUserData[UnverifiedUser].Email)
	victim := sessionCookieFor(t, app, victimID)
	victimSessionID := sessionIDByToken(t, db, victim.Value)

	rr := doDelete(t, app, strings.Replace(PathSession, "{id}", victimSessionID, 1), cookie)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// The victim's session is still valid.
	_, err := app.storage.Session.Validate(t.Context(), nil, victim.Value)
	assert.NoError(t, err)
}

func Test_Integration_RevokeSessionByIDNotFound(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// A well-formed but unknown UUID, and a malformed id, both resolve to 404 without
	// leaking whether the id was valid.
	unknown := "00000000-0000-0000-0000-000000000000"
	rr := doDelete(t, app, strings.Replace(PathSession, "{id}", unknown, 1), cookie)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = doDelete(t, app, strings.Replace(PathSession, "{id}", "not-a-uuid", 1), cookie)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func Test_Integration_RevokeSessionByIDRequiresAuth(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doDelete(t, app, strings.Replace(PathSession, "{id}", "some-id", 1), nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// Only the caller's own sessions are listed (never another user's).
func Test_Integration_ListSessionsScopedToUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// Another user with an active session that must not appear in the listing.
	otherUserID := userID(t, db, TestUserData[UnverifiedUser].Email)
	_ = sessionCookieFor(t, app, otherUserID)

	rr := doGet(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	resp := decodeSessionList(t, rr)
	require.Len(t, resp.Data.Sessions, 1)
	assert.Equal(t, sessionIDByToken(t, db, cookie.Value), resp.Data.Sessions[0].ID)
}

// Expired sessions are excluded from the listing.
func Test_Integration_ListSessionsExcludesExpired(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// Insert an already-expired session for the same user directly.
	uid := userID(t, db, TestUserData[DefaultUser].Email)
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent)
		 VALUES ($1, $2, $3, '', '')`,
		uid, auth.HashToken("expired-token"), time.Now().Add(-time.Hour))
	require.NoError(t, err)

	rr := doGet(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	resp := decodeSessionList(t, rr)
	require.Len(t, resp.Data.Sessions, 1, "expired sessions must not be listed")
	assert.Equal(t, sessionIDByToken(t, db, cookie.Value), resp.Data.Sessions[0].ID)
}
