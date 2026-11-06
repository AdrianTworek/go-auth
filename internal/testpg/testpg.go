// Package testpg starts throwaway Postgres containers and applies the library's
// migrations to them. It is test infrastructure: only _test.go files import it, which is
// what keeps testcontainers, the Docker client and golang-migrate out of the builds of
// anyone who depends on go-auth.
package testpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	pgContainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Run starts a postgres:17 container and returns a connection to its default database.
// The container is removed by testcontainers' reaper when the test binary exits, or
// earlier by Terminate.
func Run(ctx context.Context) (*sql.DB, *pgContainer.PostgresContainer, error) {
	ctr, err := pgContainer.Run(
		ctx, "postgres:17",
		pgContainer.WithDatabase("postgres"),
		pgContainer.WithUsername("postgres"),
		pgContainer.WithPassword("postgres"),
		// Integration tests run in parallel, and every request a test makes builds a client
		// with its own pool. Peak use is ~35 connections with 11 tests in flight; the
		// raised limit keeps a bigger machine or a higher -parallel off the default 100.
		testcontainers.WithCmdArgs("-c", "max_connections=500"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				// A ceiling, not a cost: a healthy container is ready in a second or two.
				// It was 5s, which a loaded machine or CI runner exceeds — every failure
				// it produced was spurious.
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("could not run postgres test container %w", err)
	}
	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, nil, fmt.Errorf("could not get connection string for postgres test container %w", err)
	}

	db, err := sql.Open("postgres", connStr)
	return db, ctr, err
}

// Terminate removes a container started by Run.
func Terminate(ctr *pgContainer.PostgresContainer) error {
	return testcontainers.TerminateContainer(ctr)
}

// Migrate applies every migration in cmd/migrate/migrations to db.
func Migrate(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not initiate postgres driver for migrations %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(migrationsURL(), "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not initiate database instance for migrations %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("could not run database migrations %w", err)
	}
	return nil
}

// migrationsURL locates cmd/migrate/migrations from this file, so it does not depend on
// the working directory of whichever package's tests are running.
func migrationsURL() string {
	_, b, _, _ := runtime.Caller(0)
	return "file://" + filepath.Join(filepath.Dir(b), "..", "..", "cmd", "migrate", "migrations")
}
