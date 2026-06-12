package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

var TokenDuration = 5 * time.Minute

type Verification struct {
	ID        string                  `json:"id" db:"id"`
	Intent    auth.VerificationIntent `json:"intent" db:"intent"`
	UserID    *auth.NullString        `json:"userId" db:"user_id"`
	Email     *auth.NullString        `json:"email" db:"email"`
	Value     string                  `json:"-" db:"value"`
	ExpiresAt time.Time               `json:"expiresAt" db:"expires_at"`
	DbTimestamps
}

func NewVerification(i auth.VerificationIntent, email, userID *auth.NullString) *Verification {
	if email == nil {
		email = auth.NewNullString("")
	}
	if userID == nil {
		userID = auth.NewNullString("")
	}

	return &Verification{
		Intent: i,
		Email:  email,
		UserID: userID,
	}
}

type VerificationStore struct {
	db *sqlx.DB
}

func (s *VerificationStore) Create(ctx context.Context, tx *sqlx.Tx, verification *Verification) (string, error) {
	query := `
		INSERT INTO verifications (user_id, value, expires_at, intent, email)
		VALUES (:user_id, :value, :expires_at, :intent, :email)
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	verificationToken, err := auth.GenerateSecureToken(auth.EmailTokenBytes)
	if err != nil {
		return "", err
	}
	// Store only the hash; the raw token is returned to the caller (emailed to the user).
	verification.Value = auth.HashToken(verificationToken)
	verification.ExpiresAt = time.Now().Add(TokenDuration)

	if tx != nil {
		_, err = tx.NamedExecContext(ctx, query, verification)
	} else {
		_, err = s.db.NamedExecContext(ctx, query, verification)
	}
	if err != nil {
		return "", err
	}

	return verificationToken, nil
}

// Consume atomically validates and deletes a verification token, returning the row
// if it was valid (matching intent and not expired). Running it inside a transaction
// makes token use strictly single-use: concurrent callers race on the same DELETE so
// only one succeeds, and a rollback restores the token if the surrounding operation
// fails.
func (s *VerificationStore) Consume(ctx context.Context, tx *sqlx.Tx, tokenStr string, intent auth.VerificationIntent) (*Verification, error) {
	query := `
		DELETE FROM verifications
		WHERE value = $1 AND intent = $2 AND expires_at > NOW()
		RETURNING *
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token := NewVerification(intent, nil, nil)
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, token, query, auth.HashToken(tokenStr), intent)
	} else {
		err = s.db.GetContext(ctx, token, query, auth.HashToken(tokenStr), intent)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return token, nil
}

func (s *VerificationStore) Delete(ctx context.Context, tx *sqlx.Tx, token string) error {
	query := `
		DELETE FROM verifications 
		WHERE value = $1
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	hashed := auth.HashToken(token)
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, hashed)
	} else {
		_, err = s.db.ExecContext(ctx, query, hashed)
	}
	if err != nil {
		return err
	}

	return nil
}

func (s *VerificationStore) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM verifications WHERE expires_at < NOW()`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, query)
	return err
}
