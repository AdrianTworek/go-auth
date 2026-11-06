package core

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// These tests reach below the HTTP seam, which the feature's testing plan otherwise
// avoids. The exception is deliberate and narrow: what is under test here is atomicity
// under concurrency, and two simultaneous requests is not something the endpoint seam
// can express.

// enrolTOTP stores a confirmed credential directly, standing in for an enrolment that
// slice 04's endpoints will perform. The secret is not encrypted here because nothing in
// this file decrypts it — these tests are about the store's guarantees, not the crypto.
func enrolTOTP(t *testing.T, app *TestApp, userID string) *store.TOTPCredential {
	t.Helper()

	require.NoError(t, app.storage.TOTP.Upsert(t.Context(), nil, &store.TOTPCredential{
		UserID: userID,
		Secret: []byte("ciphertext"),
		Nonce:  []byte("nonce-value-1"),
	}))
	require.NoError(t, app.storage.TOTP.Confirm(t.Context(), nil, userID, time.Now().UTC()))

	cred, err := app.storage.TOTP.GetForUser(t.Context(), nil, userID)
	require.NoError(t, err)
	return cred
}

// Test_Integration_ClaimStep_IsAtomic is the replay guard's reason for existing. A TOTP
// code stays valid for its whole window, so a code observed in transit could otherwise
// be submitted alongside the legitimate one and both would be accepted: a read-then-write
// check passes twice when two requests interleave. Exactly one claim may win.
func Test_Integration_ClaimStep_IsAtomic(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	enrolTOTP(t, app, uid)

	const concurrent = 8
	const step = int64(58000000)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		claimed int
	)
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := app.storage.TOTP.ClaimStep(t.Context(), nil, uid, step)
			require.NoError(t, err)
			if ok {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, claimed, "exactly one concurrent claim of the same step may succeed")
}

func Test_Integration_ClaimStep_RejectsReplayAndRewind(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	enrolTOTP(t, app, uid)

	claim := func(step int64) bool {
		ok, err := app.storage.TOTP.ClaimStep(t.Context(), nil, uid, step)
		require.NoError(t, err)
		return ok
	}

	assert.True(t, claim(100), "the first step claimed should succeed")
	assert.False(t, claim(100), "the same step is a replay")
	assert.False(t, claim(99), "an earlier step is a replay from within the skew window")
	assert.True(t, claim(101), "a later step is a fresh code")
}

func Test_Integration_ClaimStep_UnknownUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	// No enrolment: there is no row to claim, which is not an error — the caller
	// rejects the code either way.
	uid := userID(t, db, TestUserData[DefaultUser].Email)
	ok, err := app.storage.TOTP.ClaimStep(t.Context(), nil, uid, 100)
	require.NoError(t, err)
	assert.False(t, ok)
}

// Test_Integration_Upsert_ResetsEnrolmentState covers the case of a user who mis-scanned
// and started again. Carrying the previous attempt's confirmation forward would activate
// a factor nobody proved; carrying its step forward would reject the new secret's first
// code.
func Test_Integration_Upsert_ResetsEnrolmentState(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	enrolTOTP(t, app, uid)

	ok, err := app.storage.TOTP.ClaimStep(t.Context(), nil, uid, 500)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, app.storage.TOTP.Upsert(t.Context(), nil, &store.TOTPCredential{
		UserID: uid,
		Secret: []byte("second-ciphertext"),
		Nonce:  []byte("nonce-value-2"),
	}))

	cred, err := app.storage.TOTP.GetForUser(t.Context(), nil, uid)
	require.NoError(t, err)
	assert.Equal(t, []byte("second-ciphertext"), cred.Secret)
	assert.False(t, cred.Confirmed(), "re-enrolment must start unconfirmed")
	assert.Nil(t, cred.LastUsedStep, "re-enrolment must clear the replay marker")

	// Proof the marker really is clear: a step already spent under the old secret is
	// claimable again under the new one.
	ok, err = app.storage.TOTP.ClaimStep(t.Context(), nil, uid, 500)
	require.NoError(t, err)
	assert.True(t, ok)
}

func Test_Integration_Confirm_OnlyOnce(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)

	t.Run("no enrolment to confirm", func(t *testing.T) {
		err := app.storage.TOTP.Confirm(t.Context(), nil, uid, time.Now().UTC())
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("already confirmed", func(t *testing.T) {
		enrolTOTP(t, app, uid)
		err := app.storage.TOTP.Confirm(t.Context(), nil, uid, time.Now().UTC())
		assert.ErrorIs(t, err, store.ErrNotFound)
	})
}

func Test_Integration_TOTPCredential_NotFound(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	_, err := app.storage.TOTP.GetForUser(t.Context(), nil, uid)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func Test_Integration_BackupCodes_SingleUse(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	otherUID := userID(t, db, TestUserData[UnverifiedUser].Email)

	codes := []string{"AAAAA-11111", "BBBBB-22222", "CCCCC-33333"}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, auth.HashToken(auth.NormalizeBackupCode(c)))
	}
	require.NoError(t, app.storage.BackupCode.CreateMany(t.Context(), nil, uid, hashes))

	countUnused := func(user string) int {
		n, err := app.storage.BackupCode.CountUnused(t.Context(), nil, user)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, len(codes), countUnused(uid))

	consume := func(user, code string) error {
		_, err := app.storage.BackupCode.Consume(t.Context(), nil, user, auth.HashToken(auth.NormalizeBackupCode(code)))
		return err
	}

	t.Run("spending a code works once", func(t *testing.T) {
		require.NoError(t, consume(uid, codes[0]))
		assert.Equal(t, len(codes)-1, countUnused(uid))
	})

	t.Run("the same code then fails", func(t *testing.T) {
		assert.ErrorIs(t, consume(uid, codes[0]), store.ErrNotFound)
		assert.Equal(t, len(codes)-1, countUnused(uid), "a failed spend must not change the count")
	})

	t.Run("a code typed in a different form still works", func(t *testing.T) {
		require.NoError(t, consume(uid, "bbbbb22222"))
	})

	t.Run("an unknown code fails", func(t *testing.T) {
		assert.ErrorIs(t, consume(uid, "ZZZZZ-99999"), store.ErrNotFound)
	})

	// Scoping: another user's valid code is as unusable as a code that never existed,
	// and answers the same way.
	t.Run("another user's code fails", func(t *testing.T) {
		assert.ErrorIs(t, consume(otherUID, codes[2]), store.ErrNotFound)
		assert.Equal(t, 0, countUnused(otherUID))
	})
}

// Test_Integration_BackupCodes_DeleteForUser is the guarantee behind regenerating: a
// retired set has to be gone, not flagged, or codes the user believes are invalid still
// open their account.
func Test_Integration_BackupCodes_DeleteForUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	retired := auth.HashToken(auth.NormalizeBackupCode("AAAAA-11111"))

	require.NoError(t, app.storage.BackupCode.CreateMany(t.Context(), nil, uid, []string{retired}))
	require.NoError(t, app.storage.BackupCode.DeleteForUser(t.Context(), nil, uid))

	_, err := app.storage.BackupCode.Consume(t.Context(), nil, uid, retired)
	assert.ErrorIs(t, err, store.ErrNotFound)

	n, err := app.storage.BackupCode.CountUnused(t.Context(), nil, uid)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func Test_Integration_BackupCodes_CreateManyEmpty(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)
	assert.NoError(t, app.storage.BackupCode.CreateMany(t.Context(), nil, uid, nil))
}

func Test_Integration_ExistsConfirmed(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)

	exists, err := app.storage.TOTP.ExistsConfirmed(t.Context())
	require.NoError(t, err)
	assert.False(t, exists, "no enrolments yet")

	// An unconfirmed enrolment does not count: nobody has been downgraded by switching
	// the capability off if nobody ever activated it.
	require.NoError(t, app.storage.TOTP.Upsert(t.Context(), nil, &store.TOTPCredential{
		UserID: uid,
		Secret: []byte("ciphertext"),
		Nonce:  []byte("nonce-value-1"),
	}))
	exists, err = app.storage.TOTP.ExistsConfirmed(t.Context())
	require.NoError(t, err)
	assert.False(t, exists, "an unconfirmed enrolment is not an active factor")

	require.NoError(t, app.storage.TOTP.Confirm(t.Context(), nil, uid, time.Now().UTC()))
	exists, err = app.storage.TOTP.ExistsConfirmed(t.Context())
	require.NoError(t, err)
	assert.True(t, exists)
}

// Test_Integration_Migration_ChallengeIntent is a migration check rather than a store
// check: verifications.intent is a Postgres enum, so the challenge needed a new value
// added to the type. golang-migrate runs each migration in a transaction, and a value
// added to an enum cannot be used in that same transaction — so this asserts the ALTER
// TYPE actually took effect, which nothing else in slice 02 would notice.
func Test_Integration_Migration_ChallengeIntent(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := userID(t, db, TestUserData[DefaultUser].Email)

	token, err := app.storage.Verification.Create(t.Context(), nil, &store.Verification{
		Intent:    auth.TwoFactorChallengeIntent,
		UserID:    auth.NewNullString(uid),
		Email:     auth.NewNullString(""),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	require.NoError(t, err, "the two_factor_challenge enum value must exist after migration 000006")

	consumed, err := app.storage.Verification.Consume(t.Context(), nil, token, auth.TwoFactorChallengeIntent)
	require.NoError(t, err)
	assert.Equal(t, uid, consumed.UserID.String)

	// Single-use, like every other verification token.
	_, err = app.storage.Verification.Consume(t.Context(), nil, token, auth.TwoFactorChallengeIntent)
	assert.ErrorIs(t, err, store.ErrNotFound)
}
