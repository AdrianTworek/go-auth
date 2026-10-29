package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

var ErrDuplicateEmail = errors.New("duplicate email")

// mapDuplicateEmail converts a Postgres unique-violation (23505) into
// ErrDuplicateEmail. users has a single unique constraint (email), so any unique
// violation maps to a duplicate email.
func mapDuplicateEmail(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return ErrDuplicateEmail
	}
	return err
}

type User struct {
	BaseEntity
	Email         string           `json:"email" db:"email"`
	Password      auth.Hashed      `json:"-" db:"password"`
	EmailVerified bool             `json:"emailVerified" db:"email_verified"`
	AvatarURL     *auth.NullString `json:"avatarURL" db:"avatar_url"`
	AvatarSource  *auth.NullString `json:"avatarSource" db:"avatar_source"`
}

func NewUser(email string, emailVerified bool, avatarURL, avatarSource *auth.NullString) *User {
	if avatarURL == nil {
		avatarURL = auth.NewNullString("")
	}
	if avatarSource == nil {
		avatarSource = auth.NewNullString("")
	}

	return &User{
		Email:         email,
		EmailVerified: emailVerified,
		AvatarURL:     avatarURL,
		AvatarSource:  avatarSource,
	}
}

type UserStore struct {
	db *sqlx.DB
}

// LockForUpdate takes a row lock on the user for the rest of the transaction. Callers
// that decide something by counting a user's related rows need it: without the lock two
// concurrent unlinks each see one sign-in method remaining, both proceed, and the user
// is left with none.
func (s *UserStore) LockForUpdate(ctx context.Context, tx *sqlx.Tx, id string) error {
	query := `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var locked int
	if err := tx.GetContext(ctx, &locked, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (s *UserStore) Create(ctx context.Context, tx *sqlx.Tx, user *User) error {
	query := `
    INSERT INTO users (email, password, email_verified, avatar_url, avatar_source)
    VALUES (:email, :password, :email_verified, :avatar_url, :avatar_source)
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx == nil {
		_, err = s.db.NamedExecContext(ctx, query, user)
	} else {
		_, err = tx.NamedExecContext(ctx, query, user)
	}

	if err != nil {
		return mapDuplicateEmail(err)
	}

	return nil
}

func (s *UserStore) GetByID(ctx context.Context, tx *sqlx.Tx, id string) (*User, error) {
	query := `
    SELECT * FROM users
    WHERE id = $1
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	user := &User{}
	var err error
	if tx == nil {
		err = s.db.GetContext(ctx, user, query, id)
	} else {
		err = tx.GetContext(ctx, user, query, id)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *UserStore) GetByEmail(ctx context.Context, tx *sqlx.Tx, email string) (*User, error) {
	query := `
    SELECT * FROM users
    WHERE email = $1
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	user := &User{}
	var err error
	if tx == nil {
		err = s.db.GetContext(ctx, user, query, email)
	} else {
		err = tx.GetContext(ctx, user, query, email)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *UserStore) Update(ctx context.Context, tx *sqlx.Tx, user *User) (*User, error) {
	query := `
	UPDATE users
	SET 
		email = :email, 
		password = :password,
		email_verified = :email_verified,
		avatar_url = :avatar_url,
		avatar_source = :avatar_source
	WHERE id = :id
	RETURNING *
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var (
		err  error
		rows *sqlx.Rows
	)
	if tx == nil {
		rows, err = s.db.NamedQueryContext(ctx, query, user)
	} else {
		query, err := tx.PrepareNamedContext(ctx, query)
		if err != nil {
			return nil, err
		}
		rows, err = query.QueryxContext(ctx, user)
		if err != nil {
			return nil, mapDuplicateEmail(err)
		}
	}
	if err != nil {
		return nil, mapDuplicateEmail(err)
	}

	updated := &User{}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.StructScan(updated); err != nil {
			return nil, err
		}
	}

	return updated, nil
}
