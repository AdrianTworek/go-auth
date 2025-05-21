package mailer

import (
	"fmt"

	"github.com/spf13/viper"
)

type Mailer interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendPasswordChangedEmail(to string) error
	SendMagicLinkEmail(to, token string) error
}

type AppMailer struct {
	from string
}

func (m *AppMailer) SendVerificationEmail(to, token string) error {
	// Send an mail to the user with the verification token
	fmt.Printf("Sending verification mail to %s from %s with token: %s\n", to, m.from, token)
	return nil
}

func (m *AppMailer) SendPasswordResetEmail(to, token string) error {
	// Send an mail to the user with the password reset token
	fmt.Printf("Sending password reset mail to %s from %s with token: %s\n", to, m.from, token)
	return nil
}

func (m *AppMailer) SendPasswordChangedEmail(to string) error {
	// Send an mail to the user that the password has been changed
	fmt.Printf("Password has beed changed successfully for user: %s\n", to)
	return nil
}

func (m *AppMailer) SendMagicLinkEmail(to, token string) error {
	// Send an mail to the user with the magic link token
	backendURL := viper.GetString("BASE_URL")
	magicLinkURL := fmt.Sprintf("%s/auth/magic-link/%s", backendURL, token)
	fmt.Printf("Sending magic link mail to %s from %s url: %s\n", to, m.from, magicLinkURL)
	return nil
}

func New() *AppMailer {
	return &AppMailer{
		from: "autosend@go-auth.com",
	}
}
