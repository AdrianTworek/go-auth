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
	OAuthProvider *auth.NullString `json:"oauthProvider" db:"oauth_provider"`
	OAuthID       *auth.NullString `json:"oauthID" db:"oauth_id"`
}

func NewUser(email string, emailVerified bool, avatarURL, avatarSource, oauthProvider, oauthID *auth.NullString) *User {
	if avatarURL == nil {
		avatarURL = auth.NewNullString("")
	}
	if avatarSource == nil {
		avatarSource = auth.NewNullString("")
	}
	if oauthProvider == nil {
		oauthProvider = auth.NewNullString("")
	}
	if oauthID == nil {
		oauthID = auth.NewNullString("")
	}

	return &User{
		Email:         email,
		EmailVerified: emailVerified,
		AvatarURL:     avatarURL,
		AvatarSource:  avatarSource,
		OAuthProvider: oauthProvider,
		OAuthID:       oauthID,
	}
}

type UserStore struct {
	db *sqlx.DB
}

func (s *UserStore) Create(ctx context.Context, tx *sqlx.Tx, user *User) error {
	query := `
    INSERT INTO users (email, password, email_verified, avatar_url, avatar_source, oauth_provider, oauth_id)
    VALUES (:email, :password, :email_verified, :avatar_url, :avatar_source, :oauth_provider, :oauth_id)
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
		avatar_source = :avatar_source,
		oauth_provider = :oauth_provider,
		oauth_id = :oauth_id
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
