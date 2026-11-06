package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/mock"
	"github.com/testcontainers/testcontainers-go"
	pgContainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

type MockMailer struct {
	mock.Mock
}

func (m *MockMailer) SendVerificationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockMailer) SendPasswordResetEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockMailer) SendPasswordChangedEmail(to string) error {
	args := m.Called(to)
	return args.Error(0)
}

func (m *MockMailer) SendMagicLinkEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockMailer) SendEmailChangeEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockMailer) SendEmailChangeNotification(to, newEmail, cancelToken string) error {
	args := m.Called(to, newEmail, cancelToken)
	return args.Error(0)
}

func (m *MockMailer) SendEmailChangeCompletedNotification(to, newEmail string) error {
	args := m.Called(to, newEmail)
	return args.Error(0)
}

type ChiParamExtractor struct {
	Req *http.Request
}

func (c *ChiParamExtractor) GetParam(key string) string {
	return chi.URLParam(c.Req, key)
}

type TestApp struct {
	env     *Env
	config  *AuthConfig
	mailer  *MockMailer
	storage *store.Storage
	// nowFn, when set, replaces the clock on every client Router() builds. Router()
	// constructs a fresh AuthClient per request, so a test cannot reach in and swap the
	// field itself; this threads one shared clock through all of them, which is what
	// makes TOTP skew, replay and challenge expiry testable without sleeping.
	nowFn func() time.Time
}

func NewTestApp(env *Env, c *AuthConfig) (*TestApp, error) {
	db, err := db.NewPostgres(env.DSN)
	if err != nil {
		fmt.Println("Error connecting to the database")
		fmt.Println(err)
		return nil, err
	}

	s := store.NewStorage(db)

	m := &MockMailer{}
	c.Mailer = m

	return &TestApp{
		env:     env,
		config:  c,
		mailer:  m,
		storage: s,
	}, nil
}

func (a *TestApp) Router() *chi.Mux {
	r := chi.NewRouter()

	// Rate limiting is on by default in the library, but Router() builds a fresh
	// client (and in-memory limiter) per call and most tests share the constant
	// httptest RemoteAddr, so default it OFF here. Tests that exercise rate limiting
	// build their own client with an explicit RateLimit config.
	rl := a.config.RateLimit
	if rl == nil {
		rl = &RateLimitConfig{Enabled: Ptr(false)}
	}

	ac, err := NewAuthClient(&AuthConfig{
		Db: &DatabaseConfig{
			Dsn: a.env.DSN,
		},
		Mailer:        a.mailer,
		Session:       a.config.Session,
		Tokens:        a.config.Tokens,
		OAuth:         a.config.OAuth,
		Hooks:         a.config.Hooks,
		BaseURL:       a.config.BaseURL,
		SessionSecret: a.env.SessionSecret,
		RateLimit:     rl,
		TrustedProxy:  a.config.TrustedProxy,
		Password:      a.config.Password,
		MFA:           a.config.MFA,
	})
	if err != nil {
		return nil
	}
	if a.nowFn != nil {
		ac.now = a.nowFn
	}

	// Mirrors the chi adapter, but inlined: the core package's tests can't import an
	// adapter (it would form an import cycle), so this wires the same canonical path
	// constants by hand. The real adapters are covered by the conformance test.
	mw := ac.AuthMiddleware()

	r.Post(PathRegister, ac.RegisterHandler())
	r.Post(PathLogin, ac.LoginHandler())
	r.Get(PathVerifyEmail, func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&ChiParamExtractor{Req: r})(w, r)
	})
	r.Post(PathResendVerification, ac.ResendVerificationHandler())

	r.Post(PathSendMagicLink, ac.SendMagicLinkHandler())
	r.Get(PathMagicLink, func(w http.ResponseWriter, r *http.Request) {
		ac.CompleteMagicLinkSignInHandler(&ChiParamExtractor{Req: r})(w, r)
	})

	r.Post(PathSendPasswordReset, ac.SendPasswordResetLinkHandler())
	r.Put(PathPasswordReset, func(w http.ResponseWriter, r *http.Request) {
		ac.CompletePasswordResetHandler(&ChiParamExtractor{Req: r})(w, r)
	})
	r.Get(PathConfirmEmailChange, func(w http.ResponseWriter, r *http.Request) {
		ac.ConfirmEmailChangeHandler(&ChiParamExtractor{Req: r})(w, r)
	})
	r.Get(PathCancelEmailChange, func(w http.ResponseWriter, r *http.Request) {
		ac.CancelEmailChangeHandler(&ChiParamExtractor{Req: r})(w, r)
	})

	r.With(mw).Get(PathMe, ac.GetMeHandler())
	r.With(mw).Post(PathLogout, ac.LogoutHandler())
	r.With(mw).Post(PathChangePassword, ac.ChangePasswordHandler())
	r.With(mw).Post(PathChangeEmail, ac.ChangeEmailHandler())

	r.With(mw).Get(PathSessions, ac.ListSessionsHandler())
	r.With(mw).Delete(PathSessions, ac.RevokeOtherSessionsHandler())
	r.With(mw).Delete(PathSession, ac.RevokeSessionHandler())

	r.With(mw).Get(PathAccounts, ac.ListAccountsHandler())
	r.With(mw).Delete(PathAccount, ac.UnlinkAccountHandler())

	// Gated exactly as the adapters gate it, so the "routes are absent until the
	// capability is configured" guarantee is what the tests actually exercise.
	if ac.CanUseMFA() {
		r.With(mw).Post(PathMFATOTPSetup, ac.BeginTOTPEnrolmentHandler())
		r.With(mw).Post(PathMFATOTPConfirm, ac.TOTPEnrolmentConfirmHandler())
		r.With(mw).Post(PathMFATOTPDisable, ac.DisableTOTPHandler())
		r.With(mw).Post(PathMFABackupCodes, ac.RegenerateBackupCodesHandler())
		r.With(mw).Get(PathMFAStatus, ac.MFAStatusHandler())
		// Public: the caller holds a challenge, not a session.
		r.Post(PathMFAVerify, ac.MFAVerifyHandler())
	}

	return r
}

// Returns url for migrations directory using file driver for migrations
func getMigrationPath() string {
	// Get the path to the migrations directory from the current file
	_, b, _, _ := runtime.Caller(0)
	migrationPath := filepath.Join(filepath.Dir(b), "..", "cmd", "migrate", "migrations")
	migrationDir := strings.Join([]string{"file://", migrationPath}, "")
	return migrationDir
}

func RunUpMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not initiate postgres driver for migrations %w", err)
	}

	migrationDir := getMigrationPath()
	m, err := migrate.NewWithDatabaseInstance(migrationDir, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not initiate database instance for migrations %w", err)
	}
	if err := m.Up(); err != nil {
		// If there are no new migrations, return the error but do not fail the process
		if !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("could not run database migrations %w", err)
		}
		fmt.Println("No migrations to apply")
	}

	return nil
}

func CreateTestPostgres(ctx context.Context) (*sql.DB, *pgContainer.PostgresContainer, error) {
	dbUser := "postgres"
	dbPassword := "postgres"
	dbName := "postgres"

	ctr, err := pgContainer.Run(
		ctx, "postgres:17",
		pgContainer.WithDatabase(dbName),
		pgContainer.WithUsername(dbUser),
		pgContainer.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second),
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

type TestUserType string

const (
	DefaultUser    TestUserType = "default"
	UnverifiedUser TestUserType = "unverified"
	NoPasswordUser TestUserType = "no_password"
)

var TestUserData = map[TestUserType]struct {
	Email         string
	Password      string
	EmailVerified bool
}{
	DefaultUser: {
		Email:         "test@example.com",
		Password:      "P@ssword123_0",
		EmailVerified: true,
	},
	UnverifiedUser: {
		Email:         "unverified@example.com",
		Password:      "P@ssword123_1",
		EmailVerified: false,
	},
	NoPasswordUser: {
		Email:         "no_password@example.com",
		Password:      "",
		EmailVerified: true,
	},
}

func PopulateDB(ctx context.Context, db *sql.DB) error {
	var defaultUserPassword auth.Hashed
	if err := defaultUserPassword.Set(TestUserData[DefaultUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[DefaultUser].Email, err)
	}

	var unverifiedUserPassword auth.Hashed
	if err := unverifiedUserPassword.Set(TestUserData[UnverifiedUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[UnverifiedUser].Email, err)
	}

	var noPasswordUserPassword auth.Hashed
	if err := noPasswordUserPassword.Set(TestUserData[NoPasswordUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[NoPasswordUser].Email, err)
	}

	query := `
	INSERT INTO users (email, password, email_verified) 
	VALUES ($1, $2, $3), ($4, $5, $6), ($7, $8, $9)
`

	_, err := db.ExecContext(
		ctx, query,
		TestUserData[DefaultUser].Email, defaultUserPassword, TestUserData[DefaultUser].EmailVerified,
		TestUserData[UnverifiedUser].Email, unverifiedUserPassword, TestUserData[UnverifiedUser].EmailVerified,
		TestUserData[NoPasswordUser].Email, noPasswordUserPassword, TestUserData[NoPasswordUser].EmailVerified,
	)
	if err != nil {
		return fmt.Errorf("could not insert test users data: %w", err)
	}

	return nil
}

func NewTestAuthConfig(db *DatabaseConfig, s *SessionConfig, oauth *OAuthConfig) *AuthConfig {
	if db == nil {
		// #nosec G101 -- local development/test DSN, not a real credential
		db = &DatabaseConfig{
			Dsn: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		}
	}
	if s == nil {
		s = &SessionConfig{
			LoginAfterRegister:             true,
			MagicLinkSuccessfulRedirectURL: "http://localhost:6969/success",
			MagicLinkFailedRedirectURL:     "http://localhost:6969/failed",
		}
	}

	return &AuthConfig{
		Db:            db,
		Session:       s,
		Mailer:        nil,
		OAuth:         oauth,
		BaseURL:       "http://localhost:6969",
		SessionSecret: "test-secret",
	}
}

// integrationTemplate is the database every integration test is cloned from: migrated
// and seeded once, so a test pays for a CREATE DATABASE rather than a container start,
// six migrations and three password hashes.
const integrationTemplate = "goauth_template"

// sharedPostgres is the one container the integration tests in a test binary share. It
// is started on first use, so a run that selects only unit tests never touches Docker,
// and is removed by testcontainers' reaper when the binary exits.
var sharedPostgres struct {
	once    sync.Once
	err     error
	ctr     *pgContainer.PostgresContainer
	admin   *sql.DB
	baseDSN *url.URL
	next    atomic.Int64
}

func startSharedPostgres() error {
	sharedPostgres.once.Do(func() {
		sharedPostgres.err = func() error {
			// Not a test's context: the container outlives the test that starts it.
			ctx := context.Background()
			admin, ctr, err := CreateTestPostgres(ctx)
			if err != nil {
				return err
			}
			dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
			if err != nil {
				return err
			}
			base, err := url.Parse(dsn)
			if err != nil {
				return err
			}
			sharedPostgres.ctr, sharedPostgres.admin, sharedPostgres.baseDSN = ctr, admin, base

			if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+integrationTemplate); err != nil {
				return fmt.Errorf("creating the template database: %w", err)
			}
			tmpl, err := sql.Open("postgres", databaseDSN(integrationTemplate))
			if err != nil {
				return err
			}
			if err := RunUpMigrations(tmpl); err != nil {
				_ = tmpl.Close()
				return err
			}
			if err := PopulateDB(ctx, tmpl); err != nil {
				_ = tmpl.Close()
				return err
			}
			_ = tmpl.Close()
			return sealTemplate(ctx, admin)
		}()
	})
	return sharedPostgres.err
}

// sealTemplate leaves the template with no sessions, which CREATE DATABASE ... TEMPLATE
// requires. Closing the pool is not enough: golang-migrate's driver holds a checked-out
// connection that sql.DB.Close does not reach, so those backends are terminated, and
// further connections refused so nothing can reopen one between clones.
func sealTemplate(ctx context.Context, admin *sql.DB) error {
	if _, err := admin.ExecContext(ctx, `ALTER DATABASE `+integrationTemplate+` ALLOW_CONNECTIONS false`); err != nil {
		return fmt.Errorf("sealing the template database: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var open int
		if err := admin.QueryRowContext(ctx, `
			SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()`, integrationTemplate).Scan(&open); err != nil {
			return fmt.Errorf("closing sessions on the template database: %w", err)
		}
		if open == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the template database still has %d open sessions", open)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func databaseDSN(name string) string {
	u := *sharedPostgres.baseDSN
	u.Path = "/" + name
	return u.String()
}

// newIntegrationDatabase clones the template into a database of the test's own and
// returns a connection to it and its DSN.
func newIntegrationDatabase(t *testing.T) (*sql.DB, string, error) {
	if err := startSharedPostgres(); err != nil {
		return nil, "", fmt.Errorf("starting the shared postgres container: %w", err)
	}
	name := fmt.Sprintf("goauth_test_%d", sharedPostgres.next.Add(1))
	if _, err := sharedPostgres.admin.ExecContext(t.Context(),
		`CREATE DATABASE `+name+` TEMPLATE `+integrationTemplate); err != nil {
		return nil, "", fmt.Errorf("cloning the template database: %w", err)
	}
	dsn := databaseDSN(name)
	db, err := sql.Open("postgres", dsn)
	return db, dsn, err
}

// SetupIntegration gives a test its own freshly migrated and seeded database (cloned
// from a template in a container shared by the whole test binary) and an application
// pointed at it. Under -short it skips the test instead.
func SetupIntegration(t *testing.T, c *AuthConfig) (*TestApp, *pgContainer.PostgresContainer, *sql.DB) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	// Tests use the minimum bcrypt cost. At the production default a hash takes seconds
	// under -race, and each test hashes several times; no test asserts on the cost.
	if err := auth.SetBcryptCost(bcrypt.MinCost); err != nil {
		t.Fatalf("Error setting the test bcrypt cost: %v", err)
	}

	env, err := NewEnv(true)
	if err != nil {
		t.Fatalf("Error in environment setup: %v", err)
		return nil, nil, nil
	}

	db, dsn, err := newIntegrationDatabase(t)
	if err != nil {
		t.Fatalf("Error in creating the test database: %v", err)
		return nil, nil, nil
	}
	// Point the application at this test's database.
	env.DSN = dsn

	if c == nil {
		c = NewTestAuthConfig(nil, nil, nil)
	}

	app, err := NewTestApp(env, c)
	if err != nil {
		t.Fatalf("Error in application bootstrap: %v", err)
		return nil, nil, nil
	}
	return app, sharedPostgres.ctr, db
}

// CleanupIntegration releases what SetupIntegration or CreateTestPostgres handed out,
// when the test finishes. A database on the shared container is dropped, forcibly,
// because every request in a test builds a client with its own pool; a container of the
// test's own is terminated.
func CleanupIntegration(t *testing.T, ctr *pgContainer.PostgresContainer, db *sql.DB) {
	t.Cleanup(func() {
		var name string
		if ctr == sharedPostgres.ctr {
			if err := db.QueryRowContext(context.Background(), `SELECT current_database()`).Scan(&name); err != nil {
				t.Errorf("Error resolving the test database to drop: %v", err)
			}
		}
		if err := db.Close(); err != nil {
			t.Fatalf("Error in closing database connection: %v", err)
			return
		}
		if ctr == sharedPostgres.ctr {
			if name != "" {
				if _, err := sharedPostgres.admin.ExecContext(context.Background(),
					`DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
					t.Errorf("Error dropping test database %s: %v", name, err)
				}
			}
			return
		}
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Fatalf("Error in terminating postgres test container: %v", err)
			return
		}
	})
}
