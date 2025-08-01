package core

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// TODO: Figure out how can a certain hook can prematurely respond

type AuthEventType string

const (
	EventBeforeLogin        AuthEventType = "before_login"
	EventAfterLogin         AuthEventType = "after_login"
	EventBeforeRegistration AuthEventType = "before_registration"
	EventAfterRegistration  AuthEventType = "after_registration"
	EventLogout             AuthEventType = "logout"
)

type AuthEvent struct {
	// Type of event that was triggered like EventBeforeLogin
	Type AuthEventType
	// User is optional some events won't include user
	User *store.User
	// Response writer from the request the event was sent from
	W http.ResponseWriter
	// Request object from the request the event was sent from
	R *http.Request
}

func NewAuthEvent(eventType AuthEventType, w http.ResponseWriter, r *http.Request, user *store.User) *AuthEvent {
	return &AuthEvent{
		Type: eventType,
		W:    w,
		R:    r,
		User: user,
	}
}

type HookFunc func(ctx context.Context, event *AuthEvent) error

type HookList = []HookFunc

type HookMap = map[AuthEventType]HookList

type HookStore struct {
	hooks HookMap
}

func NewHookStore(hooks HookMap) *HookStore {
	return &HookStore{
		hooks: hooks,
	}
}

// Trigger will trigger any hook that is set for that event type
func (hs *HookStore) Trigger(ctx context.Context, event *AuthEvent) error {
	hooks := hs.hooks[event.Type]
	if len(hooks) < 1 {
		slog.Info("skipping hook", "reason", "no handlers found", "type", event.Type)
		return nil
	}
	for _, hook := range hooks {
		err := hook(ctx, event)
		if err != nil {
			// Endpoint should just return Internal Server Error for most part probably
			// Maybe in the future hook could have type of error it returns or it could return
			// some standarised http error, it could also respond and end the endpoint earlier
			return err
		}
	}
	return nil
}
