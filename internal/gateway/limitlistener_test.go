package gateway

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoAccept accepts and holds connections until told, so we can exercise the
// concurrency caps deterministically.
func TestLimitListenerCaps(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := NewLimitListener(base, 3, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer ll.Close()

	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	addr := base.Addr().String()
	// Open 5 connections from the same IP (loopback). Per-IP cap is 2 and the
	// total cap is 3; either way at most 3 stay open, the rest get 421.
	dial := func() (net.Conn, string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		return c, line
	}
	rejected := 0
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		c, line := dial()
		conns = append(conns, c)
		if strings.HasPrefix(line, "421") {
			rejected++
		}
	}
	for _, c := range conns {
		c.Close()
	}
	// Per-IP cap of 2 is the binding limit for loopback: 3 rejected.
	if rejected < 3 {
		t.Fatalf("expected at least 3 rejections, got %d", rejected)
	}
}

func TestLimitListenerReleasesOnClose(t *testing.T) {
	base, _ := net.Listen("tcp", "127.0.0.1:0")
	ll := NewLimitListener(base, 1, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer ll.Close()
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			// Immediately close so the slot is released.
			c.Close()
		}
	}()
	addr := base.Addr().String()
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		io.ReadAll(c) // wait for close
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientKeyIPv6Slash64(t *testing.T) {
	k := func(s string) string {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return clientKey(a)
	}
	if a, b := k("[2001:db8:1:2::1]:25"), k("[2001:db8:1:2:ffff::9]:25"); a != b {
		t.Fatalf("same /64 keyed differently: %s vs %s", a, b)
	}
	if a, b := k("[2001:db8:1:2::1]:25"), k("[2001:db8:1:3::1]:25"); a == b {
		t.Fatal("different /64s share a key")
	}
	if got := k("192.0.2.7:25"); got != "192.0.2.7" {
		t.Fatalf("ipv4 key = %s", got)
	}
	if got := k("[::ffff:192.0.2.7]:25"); got != "192.0.2.7" {
		t.Fatalf("mapped ipv4 key = %s", got)
	}
}

// The session cap holds even though the server keeps pushing the deadline
// forward (as go-smtp does before every command).
func TestLimitListenerSessionTimeout(t *testing.T) {
	base, _ := net.Listen("tcp", "127.0.0.1:0")
	ll := NewLimitListener(base, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ll.SessionTimeout = 300 * time.Millisecond
	defer ll.Close()
	done := make(chan time.Duration, 1)
	go func() {
		c, err := ll.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		start := time.Now()
		buf := make([]byte, 1)
		for {
			c.SetReadDeadline(time.Now().Add(time.Hour)) // idle timeout reset
			if _, err := c.Read(buf); err != nil {
				done <- time.Since(start)
				return
			}
		}
	}()
	c, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Trickle a byte every 50ms: never idle, but the session must still end.
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	select {
	case d := <-done:
		if d > 2*time.Second {
			t.Fatalf("session lasted %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session cap not enforced")
	}
}
