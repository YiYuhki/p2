// Package smtpclient dials the upstream (internal) mail server. It is shared
// by the SMTP proxy and by the portal's one-time-code mailer.
package smtpclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
)

type Options struct {
	Addr               string
	HeloName           string
	StartTLS           bool
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Dial connects, greets with HeloName and optionally upgrades to TLS.
func Dial(o Options) (*smtp.Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = time.Minute
	}
	if o.HeloName == "" {
		o.HeloName = "localhost"
	}
	conn, err := net.DialTimeout("tcp", o.Addr, o.Timeout)
	if err != nil {
		return nil, err
	}
	if o.StartTLS {
		host, _, _ := net.SplitHostPort(o.Addr)
		conn, err = startTLS(conn, o.HeloName, &tls.Config{
			ServerName: host, InsecureSkipVerify: o.InsecureSkipVerify, MinVersion: tls.VersionTLS12,
		}, o.Timeout)
		if err != nil {
			return nil, err
		}
	}
	c := smtp.NewClient(conn)
	c.CommandTimeout = o.Timeout
	c.SubmissionTimeout = 5 * o.Timeout
	if err := c.Hello(o.HeloName); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ResultUnknownError reports a failure after the whole message, including
// the terminating ".", may have reached the server, without a definite SMTP
// reply: the server may or may not have accepted (and will deliver) it, so
// the caller must not simply retry.
type ResultUnknownError struct{ Err error }

func (e *ResultUnknownError) Error() string {
	return "smtp: delivery result unknown: " + e.Err.Error()
}

func (e *ResultUnknownError) Unwrap() error { return e.Err }

// IsResultUnknown reports whether err (or an error it wraps) is a
// *ResultUnknownError.
func IsResultUnknown(err error) bool {
	var u *ResultUnknownError
	return errors.As(err, &u)
}

// Send delivers one message and closes the connection. A transport failure
// after the message body was handed over (while finishing DATA or waiting
// for the final reply) is returned as a *ResultUnknownError; every other
// error means the message was not accepted.
func Send(o Options, from string, to []string, msg []byte) error {
	c, err := Dial(o)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := sendMail(c, from, to, msg); err != nil {
		return err
	}
	// The server accepted the message once DATA got its 250: a failing QUIT
	// must not be reported as a delivery failure, or callers would retry
	// (e.g. reopen a released hold) and send it twice.
	_ = c.Quit()
	return nil
}

// sendMail is smtp.Client.SendMail with failures classified by whether the
// server could have accepted the message.
func sendMail(c *smtp.Client, from string, to []string, msg []byte) error {
	var opts *smtp.MailOptions
	if !isASCII(from) || !allASCII(to) {
		opts = &smtp.MailOptions{UTF8: true}
	}
	if err := c.Mail(from, opts); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	// Until Close sends the terminating "." the server cannot accept the
	// message, so a write error here is a definite failure.
	if _, err := io.Copy(w, bytes.NewReader(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			return err // a definite reply: not accepted
		}
		return &ResultUnknownError{Err: err}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func allASCII(ss []string) bool {
	for _, s := range ss {
		if !isASCII(s) {
			return false
		}
	}
	return true
}

// startTLS performs the plaintext EHLO/STARTTLS exchange itself because
// go-smtp's client only offers STARTTLS with the fixed name "localhost".
// The returned conn replays a synthetic 220 greeting so that a fresh
// smtp.Client can issue the post-TLS EHLO with our own name.
func startTLS(conn net.Conn, helo string, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	tp := textproto.NewConn(conn)
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fail(err)
	}
	if err := tp.PrintfLine("EHLO %s", helo); err != nil {
		return fail(err)
	}
	_, ext, err := tp.ReadResponse(250)
	if err != nil {
		return fail(err)
	}
	if !strings.Contains(strings.ToUpper(ext), "STARTTLS") {
		return fail(errors.New("upstream does not offer STARTTLS"))
	}
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return fail(err)
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fail(err)
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return fail(err)
	}
	tc.SetDeadline(time.Time{})
	return &greetingConn{Conn: tc, r: io.MultiReader(strings.NewReader("220 tls ready\r\n"), tc)}, nil
}

type greetingConn struct {
	net.Conn
	r io.Reader
}

func (g *greetingConn) Read(p []byte) (int, error) { return g.r.Read(p) }
