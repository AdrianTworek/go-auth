package core

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaSnapshotPath is cmd/migrate/schema.sql, resolved from this file so the test does
// not depend on the working directory.
func schemaSnapshotPath() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(b), "..", "cmd", "migrate", "schema.sql")
}

// schemaCatalogQueries describe a database's schema as sorted, comparable text. Each one
// covers an object kind the migrations create; anything not listed here is not compared.
//
// Column order is deliberately not compared: a migrated users table carries the gaps left
// by the dropped OAuth columns, which the snapshot has no reason to reproduce, and nothing
// in the library selects by position.
var schemaCatalogQueries = map[string]string{
	"extensions": `
		SELECT extname FROM pg_extension WHERE extname <> 'plpgsql'`,
	"functions": `
		SELECT p.proname || ' ' || pg_get_functiondef(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')`,
	"enums": `
		SELECT t.typname || ': ' || string_agg(e.enumlabel, ', ' ORDER BY e.enumsortorder)
		FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public'
		GROUP BY t.typname`,
	"columns": `
		SELECT concat_ws(' | ', table_name, column_name, udt_name, is_nullable,
			coalesce(column_default, '-'), coalesce(character_maximum_length::text, '-'),
			coalesce(datetime_precision::text, '-'))
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`,
	"constraints": `
		SELECT c.conrelid::regclass::text || ' ' || c.conname || ' ' || pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
		WHERE n.nspname = 'public' AND c.conrelid <> 0
		  AND c.conrelid::regclass::text <> 'schema_migrations'`,
	"indexes": `
		SELECT indexdef FROM pg_indexes
		WHERE schemaname = 'public' AND tablename <> 'schema_migrations'`,
	"triggers": `
		SELECT pg_get_triggerdef(t.oid)
		FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND NOT t.tgisinternal`,
}

func describeSchema(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	out := make(map[string][]string, len(schemaCatalogQueries))
	for kind, q := range schemaCatalogQueries {
		rows, err := db.QueryContext(t.Context(), q)
		require.NoError(t, err, kind)
		var got []string
		for rows.Next() {
			var s string
			require.NoError(t, rows.Scan(&s), kind)
			got = append(got, s)
		}
		require.NoError(t, rows.Err(), kind)
		require.NoError(t, rows.Close(), kind)
		sort.Strings(got)
		out[kind] = got
	}
	return out
}

// schema.sql is offered to fresh installs as "the whole schema in one file", so it has to
// be exactly what running every migration produces. Apply both to separate databases on
// one server and compare what the catalog says about each.
func Test_Integration_SchemaSnapshotMatchesMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	migrated, ctr, err := CreateTestPostgres(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = migrated.Close()
		_ = ctr.Terminate(t.Context())
	})
	require.NoError(t, RunUpMigrations(migrated))

	_, err = migrated.ExecContext(t.Context(), `CREATE DATABASE snapshot`)
	require.NoError(t, err)
	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/snapshot"
	snapshot, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = snapshot.Close() })

	schemaSQL, err := os.ReadFile(schemaSnapshotPath())
	require.NoError(t, err)
	_, err = snapshot.ExecContext(t.Context(), string(schemaSQL))
	require.NoError(t, err, "schema.sql must apply cleanly to an empty database")

	want := describeSchema(t, migrated)
	got := describeSchema(t, snapshot)
	for kind := range schemaCatalogQueries {
		assert.NotEmpty(t, want[kind], "the migrated database has no %s; the catalog query is wrong", kind)
		assert.Equal(t, want[kind], got[kind], "schema.sql differs from the migrations in its %s", kind)
	}
}

// The header names the migration the snapshot was taken at, and the baselining
// instructions depend on it. A new migration folded into schema.sql must bump it too.
func TestSchemaSnapshotNamesTheLatestMigration(t *testing.T) {
	ups, err := filepath.Glob(filepath.Join(filepath.Dir(schemaSnapshotPath()), "migrations", "*.up.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, ups)
	sort.Strings(ups)
	latest := strings.TrimSuffix(filepath.Base(ups[len(ups)-1]), ".up.sql")
	version := strings.TrimLeft(strings.SplitN(latest, "_", 2)[0], "0")

	schemaSQL, err := os.ReadFile(schemaSnapshotPath())
	require.NoError(t, err)
	assert.Contains(t, string(schemaSQL), "-- Snapshot of: "+latest)
	assert.Regexp(t, regexp.MustCompile(`force `+version+`\b`), string(schemaSQL))
}
