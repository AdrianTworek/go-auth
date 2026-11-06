package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// TOTPCredential is a user's authenticator-app enrolment: the encrypted shared secret,
// whether the enrolment was ever confirmed, and the most recent time step accepted for
// it.
//
// Secret and Nonce are never serialised. Neither is LastUsedStep, which is an internal
// replay marker of no use to a caller.
type TOTPCredential struct {
	BaseEntity
	UserID string `json:"userId" db:"user_id"`
	Secret []byte `json:"-" db:"secret"`
	Nonce  []byte `json:"-" db:"nonce"`
	// ConfirmedAt is nil for an enrolment that was started but never confirmed. Such a
	// row has no effect on sign-in.
	ConfirmedAt  *time.Time `json:"confirmedAt" db:"confirmed_at"`
	LastUsedStep *int64     `json:"-" db:"last_used_step"`
}

// Confirmed reports whether this enrolment is active. An unconfirmed credential exists
// but is inert: it is a user part-way through scanning a QR code.
func (c *TOTPCredential) Confirmed() bool {
	return c.ConfirmedAt != nil
}

// BackupCode is one single-use recovery code. Only its hash is stored, and the hash is
// never serialised.
type BackupCode struct {
	BaseEntity
	UserID   string     `json:"userId" db:"user_id"`
	CodeHash string     `json:"-" db:"code_hash"`
	UsedAt   *time.Time `json:"usedAt" db:"used_at"`
}

type TOTPStore struct {
	db *sqlx.DB
}

func (s *TOTPStore) GetForUser(ctx context.Context, tx *sqlx.Tx, userID string) (*TOTPCredential, error) {
	query := `SELECT * FROM totp_credentials WHERE user_id = $1`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	cred := &TOTPCredential{}
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, cred, query, userID)
	} else {
		err = s.db.GetContext(ctx, cred, query, userID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return cred, nil
}

// Upsert stores a new unconfirmed enrolment, replacing any existing one for the user.
//
// Replacing resets both the confirmation state and the replay marker, because a user
// restarting enrolment is scanning a different secret: inheriting the previous attempt's
// confirmation would activate a factor nobody proved, and inheriting its step would
// reject the first code from the new one.
//
// Whether a user who already holds a *confirmed* factor may reach this at all is a
// policy question, and the answer is no — re-enrolling on top of a live factor would
// invalidate the authenticator they are currently relying on. That guard belongs in the
// handler, not here.
func (s *TOTPStore) Upsert(ctx context.Context, tx *sqlx.Tx, cred *TOTPCredential) error {
	query := `
		INSERT INTO totp_credentials (user_id, secret, nonce)
		VALUES (:user_id, :secret, :nonce)
		ON CONFLICT (user_id) DO UPDATE SET
			secret = EXCLUDED.secret,
			nonce = EXCLUDED.nonce,
			confirmed_at = NULL,
			last_used_step = NULL
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.NamedExecContext(ctx, query, cred)
	} else {
		_, err = s.db.NamedExecContext(ctx, query, cred)
	}
	return err
}

// Confirm activates an enrolment. It returns ErrNotFound when the user has no
// unconfirmed enrolment to activate, which covers both "never started" and "already
// confirmed" — the caller refuses either way, so they need not be told apart.
func (s *TOTPStore) Confirm(ctx context.Context, tx *sqlx.Tx, userID string, at time.Time) error {
	query := `
		UPDATE totp_credentials
		SET confirmed_at = $2
		WHERE user_id = $1 AND confirmed_at IS NULL
		RETURNING id
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var id string
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, &id, query, userID, at)
	} else {
		err = s.db.GetContext(ctx, &id, query, userID, at)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// ClaimStep records a time step as used and reports whether the claim succeeded.
//
// This is the replay guard, and it has to be one atomic statement rather than a read
// followed by a write: a code stays valid for its whole window (plus any configured
// skew), so two requests submitting the same code concurrently would both pass a
// read-then-write check. The conditional UPDATE means exactly one of them gets the row.
//
// A false return is a code that is arithmetically correct but already spent, which the
// caller must reject exactly as it rejects a wrong code. It is the same
// RETURNING-as-guard idiom the verification store uses to make a token single-use.
func (s *TOTPStore) ClaimStep(ctx context.Context, tx *sqlx.Tx, userID string, step int64) (bool, error) {
	query := `
		UPDATE totp_credentials
		SET last_used_step = $2
		WHERE user_id = $1 AND (last_used_step IS NULL OR last_used_step < $2)
		RETURNING id
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var id string
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, &id, query, userID, step)
	} else {
		err = s.db.GetContext(ctx, &id, query, userID, step)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteForUser removes a user's enrolment outright. Disabling the factor removes the
// secret rather than flagging it inactive: keeping a secret for a factor the user has
// switched off is a liability with no purpose.
func (s *TOTPStore) DeleteForUser(ctx context.Context, tx *sqlx.Tx, userID string) error {
	query := `DELETE FROM totp_credentials WHERE user_id = $1`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID)
	} else {
		_, err = s.db.ExecContext(ctx, query, userID)
	}
	return err
}

// ExistsConfirmed reports whether any user holds an active second factor. It exists for
// the one check AuthClient runs at construction, to warn when the capability has been
// switched off while users are still enrolled — so it takes no transaction and is never
// called from a request.
func (s *TOTPStore) ExistsConfirmed(ctx context.Context) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE confirmed_at IS NOT NULL)`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var exists bool
	if err := s.db.GetContext(ctx, &exists, query); err != nil {
		return false, err
	}
	return exists, nil
}

type BackupCodeStore struct {
	db *sqlx.DB
}

// CreateMany inserts a whole generated set in one statement rather than a round trip per
// code.
func (s *BackupCodeStore) CreateMany(ctx context.Context, tx *sqlx.Tx, userID string, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}

	query := `
		INSERT INTO totp_backup_codes (user_id, code_hash)
		SELECT $1, unnest($2::text[])
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, pq.Array(hashes))
	} else {
		_, err = s.db.ExecContext(ctx, query, userID, pq.Array(hashes))
	}
	return err
}

// Consume spends one backup code, atomically and exactly once. The used_at IS NULL
// predicate is what makes a code single-use: a second attempt matches no row.
//
// ErrNotFound covers an unknown code, an already-spent code and another user's code with
// one answer, which is what the caller wants — distinguishing them would tell an attacker
// which guesses were once valid.
//
// The lookup is by hash equality on the (user_id, code_hash) index rather than a
// comparison against each of the user's unused codes: the hash is unsalted and
// deterministic, so there is nothing to iterate over.
func (s *BackupCodeStore) Consume(ctx context.Context, tx *sqlx.Tx, userID, hash string) (*BackupCode, error) {
	query := `
		UPDATE totp_backup_codes
		SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		RETURNING *
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	code := &BackupCode{}
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, code, query, userID, hash)
	} else {
		err = s.db.GetContext(ctx, code, query, userID, hash)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return code, nil
}

func (s *BackupCodeStore) CountUnused(ctx context.Context, tx *sqlx.Tx, userID string) (int, error) {
	query := `SELECT count(*) FROM totp_backup_codes WHERE user_id = $1 AND used_at IS NULL`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var count int
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, &count, query, userID)
	} else {
		err = s.db.GetContext(ctx, &count, query, userID)
	}
	return count, err
}

// DeleteForUser removes every backup code a user holds, used or not. Regenerating and
// disabling both go through it: a retired set has to actually be gone, not merely
// flagged, or codes the user believes are invalid still work.
func (s *BackupCodeStore) DeleteForUser(ctx context.Context, tx *sqlx.Tx, userID string) error {
	query := `DELETE FROM totp_backup_codes WHERE user_id = $1`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID)
	} else {
		_, err = s.db.ExecContext(ctx, query, userID)
	}
	return err
}
