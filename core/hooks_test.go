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
