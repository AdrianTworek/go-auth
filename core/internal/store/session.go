package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

type Session struct {
	BaseEntity
	UserID    string    `json:"userId" db:"user_id"`
	Token     string    `json:"-" db:"token"`
	ExpiresAt time.Time `json:"expiresAt" db:"expires_at"`
	IPAddress string    `json:"ipAddress" db:"ip_address"`
	UserAgent string    `json:"userAgent" db:"user_agent"`
}

type SessionStore struct {
	db *sqlx.DB
}

func (s *SessionStore) Create(ctx context.Context, tx *sqlx.Tx, session *Session) (string, error) {
	query := `
		INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent)
		VALUES (:user_id, :token, :expires_at, :ip_address, :user_agent)
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token, err := auth.GenerateSecureToken(auth.SessionTokenBytes)
	if err != nil {
		return "", err
	}
	// Store only the hash; the raw token is returned to the caller (set as the cookie).
	// ExpiresAt is provided by the caller (AuthClient) so session-lifetime policy
	// lives in one place rather than being overridden here.
	session.Token = auth.HashToken(token)

	if tx != nil {
		_, err = tx.NamedExecContext(ctx, query, session)
	} else {
		_, err = s.db.NamedExecContext(ctx, query, session)
	}
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *SessionStore) Validate(ctx context.Context, tx *sqlx.Tx, token string) (*Session, error) {
	query := `
		SELECT * FROM sessions 
    WHERE token = $1 AND expires_at > NOW()
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	session := &Session{}
	err := s.db.GetContext(ctx, session, query, auth.HashToken(token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return session, nil
}

func (s *SessionStore) Delete(ctx context.Context, tx *sqlx.Tx, token string) error {
	query := `
		DELETE FROM sessions WHERE token = $1
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

func (s *SessionStore) Refresh(ctx context.Context, tx *sqlx.Tx, oldToken string, expiresAt time.Time) (string, error) {
	query := `
		UPDATE sessions
		SET token = $1, expires_at = $2
		WHERE token = $3
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token, err := auth.GenerateSecureToken(auth.SessionTokenBytes)
	if err != nil {
		return "", err
	}

	_, err = s.db.ExecContext(ctx, query, auth.HashToken(token), expiresAt, auth.HashToken(oldToken))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *SessionStore) DeleteForUser(ctx context.Context, tx *sqlx.Tx, userID string) error {
	query := `
		DELETE FROM sessions WHERE user_id = $1
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID)
	} else {
		_, err = s.db.ExecContext(ctx, query, userID)
	}
	if err != nil {
		return err
	}

	return nil
}

func (s *SessionStore) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, query)
	return err
}
