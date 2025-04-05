package store

import "time"

type BaseEntity struct {
	ID string `json:"id" db:"id"`
	DbTimestamps
}

type DbTimestamps struct {
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}
