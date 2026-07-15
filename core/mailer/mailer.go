package mailer

import "fmt"

type Mailer interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendPasswordChangedEmail(to string) error
	SendMagicLinkEmail(to, token string) error
	SendEmailChangeEmail(to, token string) error
}

type AppMailer struct {
	from    string
	baseURL string
}

func (m *AppMailer) SendVerificationEmail(to, token string) error {
	// Send an email to the user with the verification token
	fmt.Printf("Sending verification mail to %s from %s with token: %s\n", to, m.from, token)
	return nil
}

func (m *AppMailer) SendPasswordResetEmail(to, token string) error {
	// Send an email to the user with the password reset token
	fmt.Printf("Sending password reset mail to %s from %s with token: %s\n", to, m.from, token)
	return nil
}

func (m *AppMailer) SendPasswordChangedEmail(to string) error {
	// Send an email to the user that the password has been changed
	fmt.Printf("Password has been changed successfully for user: %s\n", to)
	return nil
}

func (m *AppMailer) SendMagicLinkEmail(to, token string) error {
	// Send an email to the user with the magic link token
	magicLinkURL := fmt.Sprintf("%s/auth/magic-link/%s", m.baseURL, token)
	fmt.Printf("Sending magic link mail to %s from %s url: %s\n", to, m.from, magicLinkURL)
	return nil
}

func (m *AppMailer) SendEmailChangeEmail(to, token string) error {
	// Send a confirmation link to the user's NEW email address; the change applies
	// only when this link is visited.
	changeURL := fmt.Sprintf("%s/auth/change-email/%s", m.baseURL, token)
	fmt.Printf("Sending email-change confirmation to %s from %s url: %s\n", to, m.from, changeURL)
	return nil
}

func New(baseURL string) *AppMailer {
	return &AppMailer{
		from:    "autosend@go-auth.com",
		baseURL: baseURL,
	}
}
