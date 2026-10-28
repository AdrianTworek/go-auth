package core

import (
	"crypto/sha1" // #nosec G505 -- mirrors the wire format under test
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hibpDigest mirrors the upstream wire format so a test can craft a stub response. It
// duplicates the implementation's hashing on purpose: the duplication *is* the assertion
// that the client speaks the documented protocol.
func hibpDigest(t *testing.T, password string) (prefix, suffix string) {
	t.Helper()
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- test mirror of the upstream API
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	return digest[:5], digest[5:]
}

// newStubHIBP serves body for any range request and records what was asked for.
func newStubHIBP(t *testing.T, status int, body string) (*hibpChecker, *http.Request) {
	t.Helper()
	var captured http.Request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = *r
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return &hibpChecker{client: srv.Client(), baseURL: srv.URL + "/"}, &captured
}

func TestHIBPChecker_SendsOnlyAPrefixAndMatchesLocally(t *testing.T) {
	const password = "hunter2"
	prefix, suffix := hibpDigest(t, password)

	// A realistic padded response: the match, plus filler the client must skip.
	body := strings.Join([]string{
		"0000000000000000000000000000000000000:3",
		suffix + ":42",
		"1111111111111111111111111111111111111:0",
	}, "\r\n")

	checker, captured := newStubHIBP(t, http.StatusOK, body)

	timesSeen, err := checker.TimesBreached(t.Context(), password)
	require.NoError(t, err)
	assert.Equal(t, 42, timesSeen)

	assert.Equal(t, "/"+prefix, captured.URL.Path, "only the five-character prefix is sent")
	assert.NotContains(t, captured.URL.String(), suffix, "the rest of the hash must never leave")
	assert.Equal(t, "true", captured.Header.Get("Add-Padding"),
		"padding keeps response size from revealing whether the prefix had hits")
	assert.NotEmpty(t, captured.Header.Get("User-Agent"), "the API requires a user agent")
}

func TestHIBPChecker_ReportsZeroWhenAbsent(t *testing.T) {
	checker, _ := newStubHIBP(t, http.StatusOK,
		"0000000000000000000000000000000000000:3\r\n1111111111111111111111111111111111111:9")

	timesSeen, err := checker.TimesBreached(t.Context(), "a-password-nobody-has-used")
	require.NoError(t, err)
	assert.Zero(t, timesSeen)
}

func TestHIBPChecker_TreatsZeroCountPaddingAsAbsent(t *testing.T) {
	const password = "hunter2"
	_, suffix := hibpDigest(t, password)

	checker, _ := newStubHIBP(t, http.StatusOK, suffix+":0")

	timesSeen, err := checker.TimesBreached(t.Context(), password)
	require.NoError(t, err)
	assert.Zero(t, timesSeen, "a zero count is padding, not a sighting")
}

// The caller turns these errors into "allow the password", so the contract that matters is
// that a bad response is an error rather than a silent zero.
func TestHIBPChecker_ErrorsOnNonSuccessStatus(t *testing.T) {
	checker, _ := newStubHIBP(t, http.StatusTooManyRequests, "slow down")

	_, err := checker.TimesBreached(t.Context(), "hunter2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprint(http.StatusTooManyRequests))
}

func TestHIBPChecker_ErrorsOnUnreadableCount(t *testing.T) {
	const password = "hunter2"
	_, suffix := hibpDigest(t, password)

	checker, _ := newStubHIBP(t, http.StatusOK, suffix+":not-a-number")

	_, err := checker.TimesBreached(t.Context(), password)
	require.Error(t, err)
}
