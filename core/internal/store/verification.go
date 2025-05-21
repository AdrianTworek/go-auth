package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/jmoiron/sqlx"
)

var (
	TokenDuration = 5 * time.Minute
)

type Verification struct {
	ID        string                  `json:"id" db:"id"`
	Intent    auth.VerificationIntent `json:"intent" db:"intent"`
	UserID    *auth.NullString        `json:"userId" db:"user_id"`
	Email     *auth.NullString        `json:"email" db:"email"`
	OTP       *auth.Hashed            `json:"-" db:"otp"`
	Value     string                  `json:"value" db:"value"`
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
	verification.Value = verificationToken
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

func (s *VerificationStore) Validate(ctx context.Context, tx *sqlx.Tx, tokenStr string, intent auth.VerificationIntent) (*Verification, error) {
	query := `
		SELECT * FROM verifications 
    WHERE value = $1 AND intent = $2 AND expires_at > NOW()
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token := NewVerification(intent, nil, nil)
	err := s.db.GetContext(ctx, token, query, tokenStr, intent)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, ErrNotFound
		default:
			return nil, err
		}
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

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, token)
	} else {
		_, err = s.db.ExecContext(ctx, query, token)
	}
	if err != nil {
		return err
	}

	return nil
}
