// Command secmail runs the secure mail gateway.
//
//	secmail -config config.yaml                          # all components
//	secmail -config config.yaml -components smtp         # SMTP proxy only
//	secmail -config config.yaml -components portal,api,worker
//	secmail dkim-keygen -out dkim.key                    # print DNS record
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/dkimutil"
	"github.com/yiyuhki/p2/internal/gateway"
	"github.com/yiyuhki/p2/internal/internalapi"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/portal"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/smtpclient"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "dkim-keygen" {
		if err := dkimKeygen(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	components := flag.String("components", "all", "comma list of smtp,portal,api,worker or all")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(*cfgPath, *components, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath, components string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	enabled := map[string]bool{}
	for _, c := range strings.Split(components, ",") {
		enabled[strings.TrimSpace(c)] = true
	}
	if enabled["all"] {
		enabled = map[string]bool{"smtp": true, "portal": true, "api": true, "worker": true}
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return fmt.Errorf("timezone: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- infrastructure ----
	var st store.Store
	switch cfg.Database.Type {
	case "postgres":
		pg, err := store.NewPostgres(ctx, cfg.Database.DSN)
		if err != nil {
			return err
		}
		st = pg
	case "memory":
		log.Warn("using in-memory database: data is lost on restart and not shared between processes")
		st = store.NewMemory()
	default:
		return fmt.Errorf("database.type: unknown %q", cfg.Database.Type)
	}
	defer st.Close()

	obj, err := storage.New(ctx, cfg.Storage)
	if err != nil {
		return err
	}

	var rdb *redis.Client
	var q queue.Queue
	var tickets portal.Tickets
	var codes portal.CodeStore
	switch cfg.Queue.Type {
	case "redis":
		rdb = redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
		if err := rdb.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer rdb.Close()
		q = queue.NewRedis(rdb, cfg.Queue.KeyPrefix, log)
		tickets = portal.NewRedisTickets(rdb, cfg.Queue.KeyPrefix)
		codes = portal.NewRedisCodes(rdb, cfg.Queue.KeyPrefix)
	case "memory":
		log.Warn("using in-memory queue: jobs are not visible to an external analyzer")
		q = queue.NewMemory()
		tickets = portal.NewMemoryTickets()
		codes = portal.NewMemoryCodes()
	default:
		return fmt.Errorf("queue.type: unknown %q", cfg.Queue.Type)
	}

	svc := service.New(st, obj, q, service.Options{
		PublicBaseURL:      cfg.Portal.PublicBaseURL,
		InternalBaseURL:    cfg.InternalAPI.AdvertiseURL,
		LinkTTL:            cfg.Portal.LinkTTL,
		AnalysisTimeout:    cfg.Analysis.Timeout,
		MaxAttempts:        cfg.Analysis.MaxAttempts,
		VerdictReuseWindow: cfg.Analysis.VerdictReuseWindow,
	}, log)

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	var shutdowns []func(context.Context) error

	// ---- SMTP proxy ----
	if enabled["smtp"] {
		var signer *dkimutil.Signer
		if cfg.DKIM.Sign {
			signer, err = dkimutil.LoadSigner(cfg.DKIM.Domain, cfg.DKIM.Selector, cfg.DKIM.PrivateKeyFile)
			if err != nil {
				return err
			}
		}
		proc := gateway.NewProcessor(svc, gateway.ProcessorOptions{
			Hostname:  cfg.SMTP.Hostname,
			GatewayID: cfg.Rewrite.GatewayID,
			Rewrite: mimeproc.Options{
				KeepInlineImages:  cfg.Rewrite.KeepInlineImages,
				SignedPassthrough: cfg.Rewrite.SignedPolicy == config.PolicyPassthrough,
				EncryptedReject:   cfg.Rewrite.EncryptedPolicy == config.PolicyReject,
			},
			LinkTTL:       cfg.Portal.LinkTTL,
			Location:      loc,
			VerifyDKIM:    cfg.DKIM.VerifyInbound,
			StripOrigDKIM: cfg.DKIM.StripOriginal,
			Signer:        signer,
		}, log)
		be := gateway.NewBackend(proc, gateway.BackendOptions{
			AcceptedDomains: cfg.SMTP.AcceptedDomains,
			Upstream:        upstreamOpts(cfg),
		}, log)
		srv := smtp.NewServer(be)
		srv.Addr = cfg.SMTP.Listen
		srv.Domain = cfg.SMTP.Hostname
		srv.MaxMessageBytes = cfg.SMTP.MaxMessageBytes
		srv.MaxRecipients = cfg.SMTP.MaxRecipients
		srv.ReadTimeout = cfg.SMTP.ReadTimeout
		srv.WriteTimeout = cfg.SMTP.WriteTimeout
		srv.EnableSMTPUTF8 = true
		if cfg.SMTP.TLSCertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.SMTP.TLSCertFile, cfg.SMTP.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("smtp tls: %w", err)
			}
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("smtp proxy listening", "addr", srv.Addr, "upstream", cfg.Upstream.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				errCh <- fmt.Errorf("smtp: %w", err)
			}
		}()
		shutdowns = append(shutdowns, srv.Shutdown)
	}

	// ---- public portal ----
	if enabled["portal"] {
		p := portal.New(st, obj, tickets, portal.Options{
			TicketTTL:         cfg.Portal.TicketTTL,
			RateLimitRPS:      cfg.Portal.RateLimitRPS,
			RateLimitBurst:    cfg.Portal.RateLimitBurst,
			TrustProxyHeaders: cfg.Portal.TrustProxyHeaders,
			Location:          loc,
			PublicBaseURL:     cfg.Portal.PublicBaseURL,
			Auth: portal.AuthOptions{
				Mode:             cfg.Portal.Auth.Mode,
				SessionSecret:    []byte(cfg.Portal.Auth.SessionSecret),
				SessionTTL:       cfg.Portal.Auth.SessionTTL,
				AllowDomainUsers: cfg.Portal.Auth.AllowDomainUsers,
				AcceptedDomains:  cfg.SMTP.AcceptedDomains,
				TrustedHeader:    cfg.Portal.Auth.TrustedHeader,
				OTPTTL:           cfg.Portal.Auth.OTPTTL,
				OTPMaxAttempts:   cfg.Portal.Auth.OTPMaxAttempts,
				OTPResendAfter:   cfg.Portal.Auth.OTPResendAfter,
				SecureCookie:     strings.HasPrefix(cfg.Portal.PublicBaseURL, "https://"),
			},
			Codes:  codes,
			Mailer: portal.NewSMTPMailer(upstreamOpts(cfg), cfg.Portal.Auth.OTPFrom),
		}, log)
		log.Info("portal recipient authentication", "mode", cfg.Portal.Auth.Mode)
		shutdowns = append(shutdowns, serveHTTP(&wg, errCh, log, "portal", cfg.Portal.Listen, p.Handler()))
	}

	// ---- internal API for the analyzer ----
	if enabled["api"] && cfg.InternalAPI.Listen != "" {
		api := internalapi.New(st, obj, svc, cfg.InternalAPI.Token, log)
		shutdowns = append(shutdowns, serveHTTP(&wg, errCh, log, "internal-api", cfg.InternalAPI.Listen, api.Handler()))
	}

	// ---- background workers ----
	if enabled["worker"] {
		wg.Add(2)
		go func() {
			defer wg.Done()
			log.Info("verdict consumer started")
			q.ConsumeResults(ctx, svc.ApplyVerdict)
		}()
		go func() {
			defer wg.Done()
			log.Info("janitor started", "interval", cfg.Analysis.JanitorInterval)
			svc.Janitor(ctx, cfg.Analysis.JanitorInterval)
		}()
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-errCh:
		stop()
	}
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, fn := range shutdowns {
		fn(sctx)
	}
	wg.Wait()
	return err
}

func upstreamOpts(cfg config.Config) smtpclient.Options {
	helo := cfg.Upstream.HeloName
	if helo == "" {
		helo = cfg.SMTP.Hostname
	}
	return smtpclient.Options{
		Addr:               cfg.Upstream.Addr,
		HeloName:           helo,
		StartTLS:           cfg.Upstream.StartTLS,
		InsecureSkipVerify: cfg.Upstream.InsecureSkipVerify,
		Timeout:            cfg.Upstream.Timeout,
	}
}

func serveHTTP(wg *sync.WaitGroup, errCh chan<- error, log *slog.Logger, name, addr string, h http.Handler) func(context.Context) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info(name+" listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("%s: %w", name, err)
		}
	}()
	return srv.Shutdown
}

func dkimKeygen(args []string) error {
	fs := flag.NewFlagSet("dkim-keygen", flag.ExitOnError)
	out := fs.String("out", "dkim.key", "private key output path")
	bits := fs.Int("bits", 2048, "RSA key size")
	selector := fs.String("selector", "secmail", "DKIM selector (for the printed DNS record)")
	domain := fs.String("domain", "example.com", "signing domain (for the printed DNS record)")
	fs.Parse(args)

	key, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Printf("private key written to %s\n\nPublish this TXT record:\n%s._domainkey.%s. IN TXT \"v=DKIM1; k=rsa; p=%s\"\n",
		*out, *selector, *domain, base64.StdEncoding.EncodeToString(pub))
	return nil
}
