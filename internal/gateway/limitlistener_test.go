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
