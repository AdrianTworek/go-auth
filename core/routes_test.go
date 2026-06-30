package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColonParamPattern(t *testing.T) {
	cases := map[string]string{
		PathRegister:      PathRegister, // no parameter -> unchanged
		PathLogin:         PathLogin,
		PathVerifyEmail:   "/auth/verify/:token",
		PathMagicLink:     "/auth/magic-link/:token",
		PathPasswordReset: "/auth/reset-password/:token",
		"/a/{x}/b/{y}":    "/a/:x/b/:y", // multiple parameters
	}
	for in, want := range cases {
		assert.Equal(t, want, ColonParamPattern(in), "ColonParamPattern(%q)", in)
	}
}
