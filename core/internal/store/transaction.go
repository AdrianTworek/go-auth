package store

import "github.com/jmoiron/sqlx"

type TransactionStore struct {
	db *sqlx.DB
}

func (s *TransactionStore) Begin() (*sqlx.Tx, error) {
	return s.db.Beginx()
}

func (s *TransactionStore) Commit(tx *sqlx.Tx) error {
	return tx.Commit()
}

func (s *TransactionStore) Rollback(tx *sqlx.Tx) error {
	return tx.Rollback()
}
