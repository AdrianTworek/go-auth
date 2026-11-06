package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewBackupCode_Shape(t *testing.T) {
	code, err := NewBackupCode()
	require.NoError(t, err)

	t.Run("two hyphenated groups of five", func(t *testing.T) {
		groups := strings.Split(code, "-")
		require.Len(t, groups, backupCodeGroups)
		for _, g := range groups {
			assert.Len(t, g, backupCodeGroupLen)
		}
	})

	t.Run("only alphabet characters", func(t *testing.T) {
		for _, r := range strings.ReplaceAll(code, "-", "") {
			assert.Contains(t, backupCodeAlphabet, string(r), "code %q", code)
		}
	})

	t.Run("excludes the ambiguous letters", func(t *testing.T) {
		for _, excluded := range []string{"I", "L", "O", "U"} {
			assert.NotContains(t, backupCodeAlphabet, excluded)
		}
	})
}

func Test_NewBackupCode_IsRandom(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		code, err := NewBackupCode()
		require.NoError(t, err)

		_, duplicate := seen[code]
		require.False(t, duplicate, "generated the same code twice: %q", code)
		seen[code] = struct{}{}
	}
}

// Test_NormalizeBackupCode_RoundTrip is the guarantee that a user is not locked out by
// how they retyped a code off a piece of paper.
func Test_NormalizeBackupCode_RoundTrip(t *testing.T) {
	code, err := NewBackupCode()
	require.NoError(t, err)

	canonical := NormalizeBackupCode(code)
	assert.Len(t, canonical, backupCodeGroups*backupCodeGroupLen)
	assert.NotContains(t, canonical, "-")

	variants := map[string]string{
		"as displayed":  code,
		"lower case":    strings.ToLower(code),
		"no hyphen":     strings.ReplaceAll(code, "-", ""),
		"space instead": strings.ReplaceAll(code, "-", " "),
		"mixed case":    strings.ToLower(code[:3]) + code[3:],
	}

	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, canonical, NormalizeBackupCode(variant))
		})
	}
}

// Test_NormalizeBackupCode_FoldsAmbiguousLetters covers the reason the alphabet omits
// them: a code can never legitimately contain O, I or L, so a user who typed one meant
// the digit it resembles.
func Test_NormalizeBackupCode_FoldsAmbiguousLetters(t *testing.T) {
	assert.Equal(t, "0", NormalizeBackupCode("O"))
	assert.Equal(t, "0", NormalizeBackupCode("o"))
	assert.Equal(t, "1", NormalizeBackupCode("I"))
	assert.Equal(t, "1", NormalizeBackupCode("l"))
	assert.Equal(t, "10", NormalizeBackupCode("L-O"))
}

func Test_NormalizeBackupCode_Idempotent(t *testing.T) {
	code, err := NewBackupCode()
	require.NoError(t, err)

	once := NormalizeBackupCode(code)
	assert.Equal(t, once, NormalizeBackupCode(once))
}
