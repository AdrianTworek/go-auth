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

// ListForUser returns the user's currently-active (unexpired) sessions, newest first.
// The Token field carries the stored hash, which callers use to flag the current
// session; it is never serialised (json:"-").
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]*Session, error) {
	query := `
		SELECT * FROM sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY created_at DESC
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	sessions := []*Session{}
	if err := s.db.SelectContext(ctx, &sessions, query, userID); err != nil {
		return nil, err
	}

	return sessions, nil
}

// DeleteOthersForUser revokes every session for the user except the one identified by
// currentToken (the raw token, hashed here for comparison), so the caller's own session
// survives a "log out everywhere else" action.
func (s *SessionStore) DeleteOthersForUser(ctx context.Context, tx *sqlx.Tx, userID, currentToken string) error {
	query := `
		DELETE FROM sessions WHERE user_id = $1 AND token <> $2
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	hashed := auth.HashToken(currentToken)
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, hashed)
	} else {
		_, err = s.db.ExecContext(ctx, query, userID, hashed)
	}

	return err
}

// DeleteByIDForUser revokes a single session by id, scoped to the owning user so one
// user can't revoke another's session. It returns ErrNotFound when no such session
// exists for the user (including when id isn't a valid UUID, which simply matches
// nothing). The deleted row is returned so the caller can tell whether it revoked the
// session backing the current request. The id is compared as text so a malformed value
// can't raise a type error.
func (s *SessionStore) DeleteByIDForUser(ctx context.Context, tx *sqlx.Tx, userID, id string) (*Session, error) {
	query := `
		DELETE FROM sessions
		WHERE user_id = $1 AND id::text = $2
		RETURNING *
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	session := &Session{}
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, session, query, userID, id)
	} else {
		err = s.db.GetContext(ctx, session, query, userID, id)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return session, nil
}

func (s *SessionStore) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, query)
	return err
}
