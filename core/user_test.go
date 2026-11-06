package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

func TestUserFromContext_AbsentOutsideTheMiddleware(t *testing.T) {
	u, ok := UserFromContext(context.Background())
	assert.False(t, ok)
	assert.Nil(t, u)

	var nilUser *store.User
	_, ok = UserFromContext(context.WithValue(context.Background(), ctxUserKey, nilUser))
	assert.False(t, ok)
}

func TestUserFromContext_MapsTheStoredUser(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	stored := &store.User{
		Email:         "someone@example.com",
		EmailVerified: true,
		AvatarURL:     auth.NewNullString("https://example.com/a.png"),
	}
	stored.ID = "8b6f6d1e-0000-4000-8000-000000000001"
	stored.CreatedAt, stored.UpdatedAt = created, created.Add(time.Hour)
	require.NoError(t, stored.Password.Set("P@ssword123_0"))

	u, ok := UserFromContext(context.WithValue(context.Background(), ctxUserKey, stored))
	require.True(t, ok)
	assert.Equal(t, &User{
		ID:            stored.ID,
		Email:         "someone@example.com",
		EmailVerified: true,
		AvatarURL:     "https://example.com/a.png",
		CreatedAt:     created,
		UpdatedAt:     created.Add(time.Hour),
	}, u)

	// A copy: mutating it cannot reach the request's stored user.
	u.Email = "changed@example.com"
	assert.Equal(t, "someone@example.com", stored.Email)

	// Nothing serialised from it can carry the hash.
	b, err := json.Marshal(u)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "password")
}

func TestUserFromContext_NullAvatarIsEmpty(t *testing.T) {
	stored := store.NewUser("someone@example.com", false, nil, nil)

	u, ok := UserFromContext(context.WithValue(context.Background(), ctxUserKey, stored))
	require.True(t, ok)
	assert.Empty(t, u.AvatarURL)
}
