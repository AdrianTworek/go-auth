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
		Create(ctx context.Context, tx *sqlx.Tx, user *User) error
		GetByID(ctx context.Context, tx *sqlx.Tx, id string) (*User, error)
		GetByEmail(ctx context.Context, tx *sqlx.Tx, email string) (*User, error)
		Update(ctx context.Context, tx *sqlx.Tx, user *User) (*User, error)
	}
	Session interface {
		Create(ctx context.Context, tx *sqlx.Tx, session *Session) (token string, err error)
		Validate(ctx context.Context, tx *sqlx.Tx, token string) (*Session, error)
		Refresh(ctx context.Context, tx *sqlx.Tx, oldToken string) (string, error)
		Delete(ctx context.Context, tx *sqlx.Tx, token string) error
		DeleteForUser(ctx context.Context, tx *sqlx.Tx, userID string) error
	}
	Verification interface {
		Create(ctx context.Context, tx *sqlx.Tx, verification *Verification) (string, error)
		Validate(ctx context.Context, tx *sqlx.Tx, tokenStr string, intent auth.VerificationIntent) (*Verification, error)
		Delete(ctx context.Context, tx *sqlx.Tx, token string) error
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
