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

	// One row in every table that references users.
	sessionCookieFor(t, app, uid)
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO verifications (value, intent, user_id, expires_at)
		 VALUES ('cascade-token', 'password_reset', $1, NOW() + INTERVAL '1 hour')`, uid)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO accounts (user_id, provider, provider_account_id, email)
		 VALUES ($1, 'github', 'cascade-provider-id', 'cascade@example.com')`, uid)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO totp_credentials (user_id, secret, nonce, confirmed_at)
		 VALUES ($1, '\x00', '\x01', NOW())`, uid)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO totp_backup_codes (user_id, code_hash)
		 VALUES ($1, 'cascade-code-hash')`, uid)
	require.NoError(t, err)

	requireCount := func(table string, want int) {
		t.Helper()
		var got int
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM `+table+` WHERE user_id = $1`, uid).Scan(&got))
		assert.Equal(t, want, got, "%s rows for the user", table)
	}
	tables := []string{"sessions", "verifications", "accounts", "totp_credentials", "totp_backup_codes"}
	for _, table := range tables {
		requireCount(table, 1)
	}

	_, err = db.ExecContext(t.Context(), `DELETE FROM users WHERE id = $1`, uid)
	require.NoError(t, err, "deleting a user must not be refused by a foreign key")

	for _, table := range tables {
		requireCount(table, 0)
	}
}
