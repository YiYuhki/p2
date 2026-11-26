package gateway

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// LimitListener bounds the number of concurrent connections a listener will
// serve, both in total and per client IP. Excess connections get a 421
// greeting and are closed immediately, protecting the server from connection
// floods and slow-loris amplification.
type LimitListener struct {
	net.Listener
	// SessionTimeout, when positive, is the longest a connection may live:
	// every read/write deadline the server sets is clamped to accept time +
	// SessionTimeout, so a client trickling bytes (slow-loris) cannot keep a
	// slot forever even though each command resets the idle timeout.
	SessionTimeout time.Duration

	max      int
	perIP    int
	log      *slog.Logger
	sem      chan struct{}
	mu       sync.Mutex
	perIPCnt map[string]int
}

// NewLimitListener wraps l. max <= 0 disables the total cap; perIP <= 0
// disables the per-IP cap.
func NewLimitListener(l net.Listener, max, perIP int, log *slog.Logger) *LimitListener {
	ll := &LimitListener{Listener: l, max: max, perIP: perIP, log: log, perIPCnt: map[string]int{}}
	if max > 0 {
		ll.sem = make(chan struct{}, max)
	}
	return ll
}

func (l *LimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				l.reject(c, "total")
				continue
			}
		}
		ip := clientKey(c.RemoteAddr())
		if !l.reserveIP(ip) {
			if l.sem != nil {
				<-l.sem
			}
			l.reject(c, "per-ip")
			continue
		}
		lc := &limitConn{Conn: c, l: l, ip: ip}
		if l.SessionTimeout > 0 {
			lc.end = time.Now().Add(l.SessionTimeout)
			_ = c.SetDeadline(lc.end)
		}
		return lc, nil
	}
}

func (l *LimitListener) reserveIP(ip string) bool {
	if l.perIP <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIPCnt[ip] >= l.perIP {
		return false
	}
	l.perIPCnt[ip]++
	return true
}

func (l *LimitListener) release(ip string) {
	if l.perIP > 0 {
		l.mu.Lock()
		if l.perIPCnt[ip]--; l.perIPCnt[ip] <= 0 {
			delete(l.perIPCnt, ip)
		}
		l.mu.Unlock()
	}
	if l.sem != nil {
		<-l.sem
	}
}

func (l *LimitListener) reject(c net.Conn, reason string) {
	if l.log != nil {
		l.log.Warn("connection rejected: limit reached", "reason", reason, "remote", c.RemoteAddr().String())
	}
	// Best-effort SMTP greeting so a well-behaved client backs off.
	_, _ = c.Write([]byte("421 4.7.0 Too many concurrent connections, try again later\r\n"))
	_ = c.Close()
}

// clientKey is the per-client bucket: the IPv4 address, or the /64 of an
// IPv6 address (one subscriber typically owns a whole /64, so per-address
// keying would let a single host open unlimited connections).
func clientKey(a net.Addr) string {
	h := a.String()
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return h
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

type limitConn struct {
	net.Conn
	l    *LimitListener
	ip   string
	end  time.Time // zero: no session cap
	once sync.Once
}

func (c *limitConn) clamp(t time.Time) time.Time {
	if !c.end.IsZero() && (t.IsZero() || t.After(c.end)) {
		return c.end
	}
	return t
}

func (c *limitConn) SetDeadline(t time.Time) error { return c.Conn.SetDeadline(c.clamp(t)) }
func (c *limitConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(c.clamp(t))
}
func (c *limitConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.clamp(t))
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.release(c.ip) })
	return err
}
