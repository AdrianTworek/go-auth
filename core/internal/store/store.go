package store

import (
	"context"
	"errors"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound = errors.New("resource not found")

	QueryTimeout = 5 * time.Second
)

type Storage struct {
	User interface {
		Create(ctx context.Context, user *User, tx *sqlx.Tx) error
		GetByID(ctx context.Context, id string, tx *sqlx.Tx) (*User, error)
		GetByEmail(ctx context.Context, email string, tx *sqlx.Tx) (*User, error)
		Update(ctx context.Context, user *User, tx *sqlx.Tx) (*User, error)
	}
	Session interface {
		Create(ctx context.Context, session *Session, tx *sqlx.Tx) (token string, err error)
		Validate(ctx context.Context, token string) (*Session, error)
		Refresh(ctx context.Context, oldToken string) (string, error)
		Delete(ctx context.Context, token string, tx *sqlx.Tx) error
		DeleteForUser(ctx context.Context, userID string, tx *sqlx.Tx) error
	}
	Verification interface {
		Create(ctx context.Context, verification *Verification, tx *sqlx.Tx) (string, error)
		Validate(ctx context.Context, tokenStr string, intent auth.VerificationIntent) (*Verification, error)
		Delete(ctx context.Context, token string, tx *sqlx.Tx) error
	}
	Transaction interface {
		Begin() (*sqlx.Tx, error)
		Commit(tx *sqlx.Tx) error
		Rollback(tx *sqlx.Tx) error
	}
}

func NewStorage(db *sqlx.DB) *Storage {
	return &Storage{
		User:         &UserStore{db: db},
		Session:      &SessionStore{db: db},
		Verification: &VerificationStore{db: db},
		Transaction:  &TransactionStore{db: db},
	}
}
