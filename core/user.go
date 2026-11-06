package core

import (
	"context"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// User is the signed-in account as seen by your own handlers. It is a copy, decoupled
// from how the library stores users: changing it cannot affect the account, and it
// never carries the password hash. AvatarURL is empty when the account has no avatar.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	AvatarURL     string    `json:"avatarURL"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// UserFromContext returns the user that AuthMiddleware authenticated for this request.
// It is how a handler you mount behind the middleware finds out who is calling:
//
//	r.With(ac.AuthMiddleware()).Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
//		user, ok := core.UserFromContext(r.Context())
//		...
//	})
//
// The second result is false when the request did not pass through AuthMiddleware. For
// gin, echo and fiber, protect your routes with the adapter's Middleware rather than
// AuthMiddleware directly, so the authenticated context reaches the framework's own.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(ctxUserKey).(*store.User)
	if !ok || u == nil {
		return nil, false
	}
	return publicUser(u), true
}

func publicUser(u *store.User) *User {
	pu := &User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
	if u.AvatarURL != nil && u.AvatarURL.Valid {
		pu.AvatarURL = u.AvatarURL.String
	}
	return pu
}
