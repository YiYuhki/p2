package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

type passProc struct{}

func (passProc) Process(_ context.Context, _ Envelope, raw []byte) ([]byte, error) { return raw, nil }

// A client trickling the message body must be cut off after DataTimeout even
// though it is never idle for a full read timeout.
func TestDataTimeout(t *testing.T) {
	up := &upstream{}
	upAddr := serve(t, up)
	be := NewBackend(passProc{}, BackendOptions{
		Upstream:    UpstreamOptions{Addr: upAddr, Timeout: 5 * time.Second},
		DataTimeout: 300 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	addr := serve(t, be)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	expect := func(prefix string) {
		t.Helper()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("waiting for %s: %v", prefix, err)
			}
			if strings.HasPrefix(line, prefix+" ") {
				return
			}
			if !strings.HasPrefix(line, prefix+"-") {
				t.Fatalf("want %s, got %q", prefix, line)
			}
		}
	}
	expect("220")
	fmt.Fprintf(c, "EHLO client\r\n")
	expect("250")
	fmt.Fprintf(c, "MAIL FROM:<a@ext.org>\r\n")
	expect("250")
	fmt.Fprintf(c, "RCPT TO:<u@example.com>\r\n")
	expect("250")
	fmt.Fprintf(c, "DATA\r\n")
	expect("354")

	start := time.Now()
	errc := make(chan error, 1)
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := fmt.Fprintf(c, "line %d\r\n", i); err != nil {
				errc <- err
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		errc <- nil
	}()
	// The server must answer (with an error) or drop us well before the
	// client finishes trickling (~5s).
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	line, _ := r.ReadString('\n')
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("DATA not cut off after %v (got %q)", d, line)
	}
	if strings.HasPrefix(line, "250") {
		t.Fatalf("slow DATA accepted: %q", line)
	}
}
