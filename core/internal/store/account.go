package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

// ErrAccountLinked reports that the provider account is already attached to some user.
// Whether that is the caller's own account or someone else's is the caller's to decide.
var ErrAccountLinked = errors.New("provider account already linked")

// Account is one link between a user and an account at an OAuth provider. Identity is
// (Provider, ProviderAccountID) — the provider's own stable identifier — never the email,
// which a provider may allow its users to set freely.
type Account struct {
	BaseEntity
	UserID            string           `json:"userId" db:"user_id"`
	Provider          string           `json:"provider" db:"provider"`
	ProviderAccountID string           `json:"-" db:"provider_account_id"`
	Email             *auth.NullString `json:"email" db:"email"`
}

type AccountStore struct {
	db *sqlx.DB
}

func (s *AccountStore) Create(ctx context.Context, tx *sqlx.Tx, account *Account) (*Account, error) {
	query := `
		INSERT INTO accounts (user_id, provider, provider_account_id, email)
		VALUES (:user_id, :provider, :provider_account_id, :email)
		RETURNING *
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var rows *sqlx.Rows
	var err error
	if tx != nil {
		rows, err = tx.NamedQuery(query, account) //nolint:rowserrcheck // closed below, error surfaced via StructScan
	} else {
		rows, err = s.db.NamedQueryContext(ctx, query, account)
	}
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, ErrAccountLinked
		}
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	created := &Account{}
	if !rows.Next() {
		if rowsErr := rows.Err(); rowsErr != nil {
			return nil, rowsErr
		}
		return nil, ErrNotFound
	}
	if err := rows.StructScan(created); err != nil {
		return nil, err
	}
	return created, nil
}

// GetByProviderAccount resolves a link by the provider's own identifier. This is the
// lookup that makes identity authoritative: an email match is only ever a candidate for
// linking, decided by policy above this layer.
func (s *AccountStore) GetByProviderAccount(ctx context.Context, tx *sqlx.Tx, provider, providerAccountID string) (*Account, error) {
	query := `SELECT * FROM accounts WHERE provider = $1 AND provider_account_id = $2`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	account := &Account{}
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, account, query, provider, providerAccountID)
	} else {
		err = s.db.GetContext(ctx, account, query, provider, providerAccountID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return account, nil
}

func (s *AccountStore) ListForUser(ctx context.Context, userID string) ([]*Account, error) {
	query := `SELECT * FROM accounts WHERE user_id = $1 ORDER BY created_at DESC`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	accounts := []*Account{}
	if err := s.db.SelectContext(ctx, &accounts, query, userID); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (s *AccountStore) CountForUser(ctx context.Context, tx *sqlx.Tx, userID string) (int, error) {
	query := `SELECT count(*) FROM accounts WHERE user_id = $1`

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

// DeleteByIDForUser removes one link, scoped to its owner. The id is compared as text so
// a non-UUID matches nothing rather than raising a type error, which keeps an unknown, a
// foreign and a malformed id indistinguishable to the caller.
func (s *AccountStore) DeleteByIDForUser(ctx context.Context, tx *sqlx.Tx, userID, id string) (*Account, error) {
	query := `DELETE FROM accounts WHERE user_id = $1 AND id::text = $2 RETURNING *`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	account := &Account{}
	var err error
	if tx != nil {
		err = tx.GetContext(ctx, account, query, userID, id)
	} else {
		err = s.db.GetContext(ctx, account, query, userID, id)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return account, nil
}
