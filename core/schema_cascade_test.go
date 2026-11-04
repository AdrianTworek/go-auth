package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Removing a user must take their rows with it. Before the cascade migration this failed
// with a foreign-key violation, so nothing in the library could delete a user at all.
//
// Asserted directly against the schema rather than through an endpoint: there is no
// deletion endpoint yet, and the behaviour under test belongs to the migration.
func Test_Integration_DeletingAUserCascadesToItsRows(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[DefaultUser].Email
	uid := userID(t, db, email)

	// A session and a pending verification, the two tables that reference users.
	sessionCookieFor(t, app, uid)
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO verifications (value, intent, user_id, expires_at)
		 VALUES ('cascade-token', 'password_reset', $1, NOW() + INTERVAL '1 hour')`, uid)
	require.NoError(t, err)

	requireCount := func(table string, want int) {
		t.Helper()
		var got int
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM `+table+` WHERE user_id = $1`, uid).Scan(&got))
		assert.Equal(t, want, got, "%s rows for the user", table)
	}
	requireCount("sessions", 1)
	requireCount("verifications", 1)

	_, err = db.ExecContext(t.Context(), `DELETE FROM users WHERE id = $1`, uid)
	require.NoError(t, err, "deleting a user must not be refused by a foreign key")

	requireCount("sessions", 0)
	requireCount("verifications", 0)
}
