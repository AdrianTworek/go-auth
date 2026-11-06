package mailer

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSMTP is just enough of an SMTP server for net/smtp's SendMail: it optionally
// advertises AUTH PLAIN, records what it was sent, and never offers STARTTLS.
type fakeSMTP struct {
	advertiseAuth bool

	mu    sync.Mutex
	auths []string // decoded AUTH PLAIN payloads
	rcpts []string
	data  string
}

func startFakeSMTP(t *testing.T, advertiseAuth bool) (*fakeSMTP, string, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	f := &fakeSMTP{advertiseAuth: advertiseAuth}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return f, host, port
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	reply := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }

	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			if f.advertiseAuth {
				reply("250-fake")
				reply("250 AUTH PLAIN")
			} else {
				reply("250 fake")
			}
		case "AUTH":
			if !f.advertiseAuth {
				reply("502 not supported")
				continue
			}
			parts := strings.Fields(line)
			decoded, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f.mu.Lock()
			f.auths = append(f.auths, string(decoded))
			f.mu.Unlock()
			reply("235 ok")
		case "MAIL":
			reply("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			reply("250 ok")
		case "DATA":
			reply("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

// A relay that does not offer AUTH (a local MTA, Mailpit in development) must still
// receive mail when no credentials are configured. Before, PlainAuth was passed
// unconditionally and SendMail refused with "server doesn't support AUTH".
func TestSMTPMailer_DeliversWithoutAuthWhenNoUsername(t *testing.T) {
	srv, host, port := startFakeSMTP(t, false)
	m, err := NewSMTP(SMTPConfig{Host: host, Port: port, From: "no-reply@example.com", BaseURL: "https://app.example.com"})
	require.NoError(t, err)

	require.NoError(t, m.SendVerificationEmail("user@example.com", "tok123"))

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Empty(t, srv.auths)
	assert.Equal(t, []string{"RCPT TO:<user@example.com>"}, srv.rcpts)
	assert.Contains(t, srv.data, "https://app.example.com/auth/verify/tok123")
}

func TestSMTPMailer_AuthenticatesWhenUsernameSet(t *testing.T) {
	srv, host, port := startFakeSMTP(t, true)
	m, err := NewSMTP(SMTPConfig{
		Host: host, Port: port, From: "no-reply@example.com",
		Username: "mailer", Password: "s3cret",
	})
	require.NoError(t, err)

	require.NoError(t, m.SendPasswordChangedEmail("user@example.com"))

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, []string{"\x00mailer\x00s3cret"}, srv.auths)
	assert.Len(t, srv.rcpts, 1)
}

// Credentials against a server that cannot take them is a misconfiguration and must
// fail loudly rather than send unauthenticated.
func TestSMTPMailer_FailsWhenUsernameSetButServerHasNoAuth(t *testing.T) {
	_, host, port := startFakeSMTP(t, false)
	m, err := NewSMTP(SMTPConfig{Host: host, Port: port, From: "no-reply@example.com", Username: "mailer", Password: "s3cret"})
	require.NoError(t, err)

	assert.ErrorContains(t, m.SendPasswordChangedEmail("user@example.com"), "AUTH")
}
