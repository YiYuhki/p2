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

// Send delivers one message and closes the connection.
func Send(o Options, from string, to []string, msg []byte) error {
	c, err := Dial(o)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SendMail(from, to, bytes.NewReader(msg)); err != nil {
		return err
	}
	return c.Quit()
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
