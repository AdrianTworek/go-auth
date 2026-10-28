package core

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- the Have I Been Pwned range API is defined in terms of SHA-1
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	hibpRangeURL  = "https://api.pwnedpasswords.com/range/"
	hibpUserAgent = "go-auth (+https://github.com/AdrianTworek/go-auth)"
	// hibpMaxResponseBytes bounds how much of a response is read. A padded range response
	// runs to a few hundred short lines, so this leaves generous headroom while refusing
	// to read forever from a misbehaving or hostile endpoint.
	hibpMaxResponseBytes = 1 << 20
)

// hibpChecker queries the Have I Been Pwned range API using k-anonymity.
type hibpChecker struct {
	client *http.Client
	// baseURL is overridable for tests only. It is deliberately not public
	// configuration: consumers who want a different source implement BreachChecker,
	// and a URL knob would invite pointing the integration at an untrusted host.
	baseURL string
}

// NewHIBPBreachChecker returns a BreachChecker backed by the public Have I Been Pwned
// range API. No API key is required for this endpoint.
//
// Neither the password nor its full hash leaves the process: only the first five hex
// characters of the SHA-1 digest are sent, and the response — every suffix sharing that
// prefix — is matched locally. Padding is requested so that response size cannot reveal
// whether the prefix had any hits.
func NewHIBPBreachChecker(timeout time.Duration) BreachChecker {
	if timeout <= 0 {
		timeout = DefaultBreachTimeout
	}
	return &hibpChecker{
		client:  &http.Client{Timeout: timeout},
		baseURL: hibpRangeURL,
	}
}

func (h *hibpChecker) TimesBreached(ctx context.Context, password string) (int, error) {
	// SHA-1 is not a security choice here. The upstream API is specified in terms of it,
	// and the digest is only ever used to build a five-character prefix and to compare
	// suffixes locally.
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- required by the upstream API, not used as a security primitive
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, hibpMaxResponseBytes))
	for scanner.Scan() {
		suffixPart, countPart, ok := strings.Cut(scanner.Text(), ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(suffixPart), suffix) {
			continue
		}

		timesSeen, err := strconv.Atoi(strings.TrimSpace(countPart))
		if err != nil {
			return 0, fmt.Errorf("hibp: unreadable count for the matching suffix: %w", err)
		}
		return timesSeen, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	// No matching suffix, so the password is absent from the corpus. Padded responses can
	// also carry zero-count filler entries, which a count of 0 handles identically.
	return 0, nil
}
