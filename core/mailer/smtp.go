package mailer

import (
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// SMTPConfig configures the reference SMTP mailer. It targets the common case of
// an authenticated submission server on port 587 (STARTTLS) — SendGrid, Mailgun,
// Amazon SES, Postmark and Gmail all support this. For a provider API or implicit
// TLS (port 465), implement the Mailer interface yourself.
type SMTPConfig struct {
	// Host is the SMTP server hostname, e.g. "smtp.sendgrid.net".
	Host string
	// Port is the submission port. Defaults to "587" when empty.
	Port string
	// Username / Password authenticate to the server (PLAIN auth over STARTTLS).
	Username string
	Password string
	// From is the envelope + header From address, e.g. "no-reply@example.com".
	From string
	// AppName, when set, is used in email subjects (e.g. "Verify your email for Acme").
	AppName string
	// BaseURL is the origin the emailed links point at (e.g. "https://example.com").
	// It is joined with the library's auth paths to build verification/reset links.
	BaseURL string
}

// SMTPMailer is a reference Mailer that delivers plain-text emails via net/smtp.
// It exists so the email flows work end to end out of the box; production senders
// will often replace it with a provider-specific implementation of Mailer.
type SMTPMailer struct {
	cfg SMTPConfig
}

// NewSMTP builds an SMTP-backed Mailer. It returns an error if the required
// Host or From fields are missing, so misconfiguration fails fast at startup
// rather than silently dropping every email.
func NewSMTP(cfg SMTPConfig) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, errors.New("mailer: SMTP Host is required")
	}
	if cfg.From == "" {
		return nil, errors.New("mailer: SMTP From is required")
	}
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &SMTPMailer{cfg: cfg}, nil
}

// send delivers one plain-text message. smtp.SendMail upgrades the connection with
// STARTTLS when the server advertises it, so credentials are not sent in the clear.
func (m *SMTPMailer) send(to, subject, body string) error {
	addr := net.JoinHostPort(m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)

	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(b.String()))
}

// subject decorates a subject line with the configured app name when present.
func (m *SMTPMailer) subject(s string) string {
	if m.cfg.AppName != "" {
		return s + " for " + m.cfg.AppName
	}
	return s
}

func (m *SMTPMailer) link(path string) string {
	return m.cfg.BaseURL + path
}

func (m *SMTPMailer) SendVerificationEmail(to, token string) error {
	url := m.link("/auth/verify/" + token)
	body := fmt.Sprintf("Welcome! Please confirm your email address by visiting:\n\n%s\n\nIf you did not create an account, you can ignore this message.", url)
	return m.send(to, m.subject("Verify your email"), body)
}

func (m *SMTPMailer) SendPasswordResetEmail(to, token string) error {
	url := m.link("/auth/reset-password/" + token)
	body := fmt.Sprintf("We received a request to reset your password. Use the link below to choose a new one:\n\n%s\n\nIf you did not request this, you can safely ignore this email.", url)
	return m.send(to, m.subject("Reset your password"), body)
}

func (m *SMTPMailer) SendPasswordChangedEmail(to string) error {
	body := "Your password was just changed. If this was you, no action is needed. If it wasn't, reset your password immediately and review your active sessions."
	return m.send(to, m.subject("Your password was changed"), body)
}

func (m *SMTPMailer) SendMagicLinkEmail(to, token string) error {
	url := m.link("/auth/magic-link/" + token)
	body := fmt.Sprintf("Here is your sign-in link:\n\n%s\n\nIt can only be used once and expires shortly. If you did not request it, you can ignore this email.", url)
	return m.send(to, m.subject("Your sign-in link"), body)
}

func (m *SMTPMailer) SendEmailChangeEmail(to, token string) error {
	url := m.link("/auth/change-email/" + token)
	body := fmt.Sprintf("Please confirm your new email address by visiting:\n\n%s\n\nThe change only takes effect once you confirm.", url)
	return m.send(to, m.subject("Confirm your new email"), body)
}

func (m *SMTPMailer) SendEmailChangeNotification(to, newEmail, cancelToken string) error {
	url := m.link("/auth/change-email/" + cancelToken + "/cancel")
	body := fmt.Sprintf("A request was made to change your account email to %s. If this was you, no action is needed — confirm using the link sent to the new address.\n\nIf this was NOT you, cancel the change here:\n\n%s", newEmail, url)
	return m.send(to, m.subject("Email change requested"), body)
}

func (m *SMTPMailer) SendEmailChangeCompletedNotification(to, newEmail string) error {
	body := fmt.Sprintf("Your account email was changed to %s. If you did not make this change, contact support immediately.", newEmail)
	return m.send(to, m.subject("Your email was changed"), body)
}
