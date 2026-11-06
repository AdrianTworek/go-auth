package core

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// claimUnverifiedAccount marks an unverified account verified on behalf of someone who
// has just proven control of its address by a route other than the account's own
// password (a magic link, or a trusted provider asserting the address), and discards
// every credential that was attached to it before that proof.
//
// An unverified account is a claim on an address, not evidence of owning it: anyone can
// register someone else's email with a password of their choosing. Without this, that
// is a pre-hijack. The attacker registers the victim's address, the victim later signs
// in by magic link or OAuth, and lands in an account whose password, sessions, linked
// providers and second factor the attacker still holds.
//
// So the proven owner gets the account and nothing else: the password is cleared (they
// can set one through the reset flow), and sessions, provider links, pending tokens and
// any second factor are removed. A legitimate user who registered with a password and
// never verified loses that password here too. That is the price of not being able to
// tell the two apart, and the reset flow recovers it.
//
// It must run inside the transaction that issues the session. The row is locked and
// re-read first, so a concurrent verification cannot be wiped after the fact.
func (ac *AuthClient) claimUnverifiedAccount(ctx context.Context, tx *sqlx.Tx, userID string) (*store.User, error) {
	if err := ac.store.User.LockForUpdate(ctx, tx, userID); err != nil {
		return nil, err
	}
	user, err := ac.store.User.GetByID(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	if user.EmailVerified {
		return user, nil
	}

	if err := ac.store.Session.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := ac.store.Verification.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := ac.store.Account.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := ac.store.BackupCode.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := ac.store.TOTP.DeleteForUser(ctx, tx, userID); err != nil {
		return nil, err
	}

	user.Password = nil
	user.EmailVerified = true
	return ac.store.User.Update(ctx, tx, user)
}
