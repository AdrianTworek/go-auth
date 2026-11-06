package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func triggerEvent(w http.ResponseWriter) *AuthEvent {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return NewAuthEvent(EventBeforeLogin, w, r, nil)
}

func hookMap(fn HookFunc) HookMap {
	return HookMap{EventBeforeLogin: {fn}}
}

func TestHookStore_NoHooksContinues(t *testing.T) {
	hs := NewHookStore(HookMap{})
	cont, err := hs.Trigger(context.Background(), triggerEvent(httptest.NewRecorder()))
	assert.True(t, cont)
	assert.NoError(t, err)
}

func TestHookStore_NilResultContinues(t *testing.T) {
	hs := NewHookStore(hookMap(func(context.Context, *AuthEvent) error { return nil }))
	cont, err := hs.Trigger(context.Background(), triggerEvent(httptest.NewRecorder()))
	assert.True(t, cont)
	assert.NoError(t, err)
}

func TestHookStore_HookError(t *testing.T) {
	rr := httptest.NewRecorder()
	hs := NewHookStore(hookMap(func(context.Context, *AuthEvent) error {
		return NewHookError(http.StatusForbidden, "blocked")
	}))

	cont, err := hs.Trigger(context.Background(), triggerEvent(rr))
	assert.False(t, cont)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "blocked")
}

func TestHookStore_HookResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	hs := NewHookStore(hookMap(func(context.Context, *AuthEvent) error {
		return NewHookResponse(http.StatusTeapot, map[string]string{"hello": "world"})
	}))

	cont, err := hs.Trigger(context.Background(), triggerEvent(rr))
	assert.False(t, cont)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTeapot, rr.Code)
	assert.Contains(t, rr.Body.String(), "world")
}

func TestHookStore_HookRedirect(t *testing.T) {
	rr := httptest.NewRecorder()
	hs := NewHookStore(hookMap(func(context.Context, *AuthEvent) error {
		return NewHookRedirect(http.StatusFound, "https://example.com")
	}))

	cont, err := hs.Trigger(context.Background(), triggerEvent(rr))
	assert.False(t, cont)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "https://example.com", rr.Header().Get("Location"))
}

func TestHookStore_PlainErrorPropagates(t *testing.T) {
	sentinel := errors.New("boom")
	hs := NewHookStore(hookMap(func(context.Context, *AuthEvent) error { return sentinel }))

	cont, err := hs.Trigger(context.Background(), triggerEvent(httptest.NewRecorder()))
	assert.False(t, cont)
	assert.ErrorIs(t, err, sentinel)
}

func TestHookStore_StopsAtFirstShortCircuit(t *testing.T) {
	called := 0
	hs := NewHookStore(HookMap{
		EventBeforeLogin: {
			func(context.Context, *AuthEvent) error {
				called++
				return NewHookError(http.StatusForbidden, "stop")
			},
			func(context.Context, *AuthEvent) error {
				called++
				return nil
			},
		},
	})

	cont, _ := hs.Trigger(context.Background(), triggerEvent(httptest.NewRecorder()))
	assert.False(t, cont)
	assert.Equal(t, 1, called) // second hook never runs
}

func TestHookStore_EventAllObservesEveryEventAfterItsOwnHooks(t *testing.T) {
	var calls []string
	hs := NewHookStore(HookMap{
		EventBeforeLogin: {func(context.Context, *AuthEvent) error {
			calls = append(calls, "specific")
			return nil
		}},
		EventAll: {func(_ context.Context, e *AuthEvent) error {
			calls = append(calls, "all:"+string(e.Type))
			return nil
		}},
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, typ := range []AuthEventType{EventBeforeLogin, EventLogout, AuthEventType("added_in_a_later_release")} {
		cont, err := hs.Trigger(context.Background(), NewAuthEvent(typ, httptest.NewRecorder(), r, nil))
		assert.True(t, cont)
		assert.NoError(t, err)
	}

	assert.Equal(t, []string{
		"specific", "all:before_login",
		"all:logout",
		"all:added_in_a_later_release",
	}, calls)
}

// The record has to be complete, so an observer sees the event even when the event's
// own hook stopped the request — and the response stays the one that hook chose.
func TestHookStore_EventAllRunsWhenASpecificHookShortCircuits(t *testing.T) {
	observed := 0
	rr := httptest.NewRecorder()
	hs := NewHookStore(HookMap{
		EventBeforeLogin: {func(context.Context, *AuthEvent) error {
			return NewHookError(http.StatusForbidden, "blocked")
		}},
		EventAll: {func(context.Context, *AuthEvent) error {
			observed++
			return nil
		}},
	})

	cont, err := hs.Trigger(context.Background(), triggerEvent(rr))
	assert.False(t, cont)
	assert.NoError(t, err)
	assert.Equal(t, 1, observed)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	plain := NewHookStore(HookMap{
		EventBeforeLogin: {func(context.Context, *AuthEvent) error { return errors.New("boom") }},
		EventAll:         {func(context.Context, *AuthEvent) error { observed++; return nil }},
	})
	_, err = plain.Trigger(context.Background(), triggerEvent(httptest.NewRecorder()))
	assert.Error(t, err)
	assert.Equal(t, 2, observed)
}

// Whatever an observer returns — a plain error or a sentinel — the request carries on
// untouched.
func TestHookStore_EventAllCannotAffectTheRequest(t *testing.T) {
	for name, result := range map[string]error{
		"plain error":   errors.New("sink unavailable"),
		"hook error":    NewHookError(http.StatusForbidden, "blocked"),
		"hook response": NewHookResponse(http.StatusTeapot, map[string]string{"hello": "world"}),
		"hook redirect": NewHookRedirect(http.StatusFound, "https://example.com"),
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			hs := NewHookStore(HookMap{EventAll: {func(context.Context, *AuthEvent) error { return result }}})

			cont, err := hs.Trigger(context.Background(), triggerEvent(rr))
			assert.True(t, cont)
			assert.NoError(t, err)
			assert.Empty(t, rr.Body.String())
			assert.Empty(t, rr.Header().Get("Location"))
		})
	}
}
