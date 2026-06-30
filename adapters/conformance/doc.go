// Package conformance holds a cross-adapter test verifying that every framework
// adapter registers the same canonical set of auth routes. It lives in its own
// package because it imports every adapter at once, which the individual adapter
// packages must not do.
package conformance
