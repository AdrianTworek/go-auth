package core

import "strings"

// Canonical request paths for the library's auth routes. They are the single source
// of truth shared by every framework adapter (and enforced by the adapter conformance
// test), so a path cannot drift between frameworks or pick up a stray trailing slash.
//
// Patterns use the "{name}" placeholder for path parameters; adapters for routers that
// use ":name" syntax (gin, echo, fiber) translate with ColonParamPattern.
const (
	PathRegister           = "/auth/register"
	PathLogin              = "/auth/login"
	PathLogout             = "/auth/logout"
	PathMe                 = "/auth/me"
	PathResendVerification = "/auth/resend-verification"
	PathVerifyEmail        = "/auth/verify/{token}"
	PathOAuthBegin         = "/auth/oauth"
	PathOAuthCallback      = "/auth/oauth/callback"
	PathSendMagicLink      = "/auth/magic-link"
	PathMagicLink          = "/auth/magic-link/{token}"
	PathSendPasswordReset  = "/auth/reset-password"         // #nosec G101 -- URL path, not a credential
	PathPasswordReset      = "/auth/reset-password/{token}" // #nosec G101 -- URL path, not a credential
)

// ColonParamPattern converts a canonical "{name}" path pattern to the ":name" form
// used by routers such as gin, echo and fiber. A pattern with no parameter is returned
// unchanged, so adapters for "{name}" routers (chi, gorilla, net/http) don't need it.
func ColonParamPattern(pattern string) string {
	if !strings.Contains(pattern, "{") {
		return pattern
	}
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '{' {
			end := strings.IndexByte(pattern[i:], '}')
			if end == -1 {
				b.WriteString(pattern[i:])
				break
			}
			b.WriteByte(':')
			b.WriteString(pattern[i+1 : i+end])
			i += end
			continue
		}
		b.WriteByte(pattern[i])
	}
	return b.String()
}
