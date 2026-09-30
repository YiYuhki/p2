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
	"net"
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
	"github.com/yiyuhki/p2/internal/dlp"
	"github.com/yiyuhki/p2/internal/dmarc"
	"github.com/yiyuhki/p2/internal/gateway"
	"github.com/yiyuhki/p2/internal/internalapi"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/notify"
	"github.com/yiyuhki/p2/internal/outbound"
	"github.com/yiyuhki/p2/internal/portal"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/smtpclient"
	"github.com/yiyuhki/p2/internal/spfutil"
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

// startupReadyTimeout bounds how long the process waits for a dependency
// (database, storage, Redis) to become reachable at boot, smoothing over
// start-ordering races in orchestrated environments before failing.
const startupReadyTimeout = 30 * time.Second

// waitReady retries connect until it succeeds or the timeout elapses, backing
// off exponentially (1s→5s). It returns the last error on timeout.
func waitReady(ctx context.Context, log *slog.Logger, name string, timeout time.Duration, connect func(context.Context) error) error {
	deadline := time.Now().Add(timeout)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := connect(ctx)
		if err == nil {
			if attempt > 1 {
				log.Info("dependency ready", "name", name, "attempts", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not ready after %s: %w", name, timeout, err)
		}
		log.Warn("dependency not ready, retrying", "name", name, "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
		}
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
		pg, err := store.Open(ctx, store.PGOptions{
			DSN:             cfg.Database.DSN,
			MaxConns:        cfg.Database.MaxConns,
			MinConns:        cfg.Database.MinConns,
			MaxConnLifetime: cfg.Database.ConnMaxLifetime,
			ReadyTimeout:    startupReadyTimeout,
			Log:             log,
		})
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

	var obj storage.Storage
	if err := waitReady(ctx, log, "storage", startupReadyTimeout, func(ctx context.Context) error {
		o, err := storage.New(ctx, cfg.Storage)
		if err != nil {
			return err
		}
		obj = o
		return nil
	}); err != nil {
		return err
	}

	var rdb *redis.Client
	var q queue.Queue
	var tickets portal.Tickets
	var codes portal.CodeStore
	switch cfg.Queue.Type {
	case "redis":
		rdb = redis.NewClient(&redis.Options{
			Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		})
		if err := waitReady(ctx, log, "redis", startupReadyTimeout, func(ctx context.Context) error {
			return rdb.Ping(ctx).Err()
		}); err != nil {
			return err
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

	// ---- outbound DLP ----
	var outSvc *outbound.Service
	if cfg.Outbound.Enabled {
		rules := make([]dlp.Rule, 0, len(cfg.DLP.Rules))
		for _, r := range cfg.DLP.Rules {
			rules = append(rules, dlp.Rule(r))
		}
		var ocr dlp.OCROptions
		if o := cfg.DLP.OCR; o.Enabled {
			if err := dlp.CheckTesseract(o.Command, o.Languages); err != nil {
				return fmt.Errorf("dlp.ocr: %w", err)
			}
			ocr = dlp.OCROptions{
				Engine:    dlp.NewTesseract(o.Command, o.Languages, o.PSM, o.MaxProcesses),
				MaxImages: o.MaxImages, MinPixels: o.MinPixels, Timeout: o.Timeout,
				TotalTimeout: o.TotalTimeout, Concurrency: o.Concurrency,
			}
			log.Info("dlp OCR enabled", "engine", "tesseract", "languages", o.Languages)
		}
		o := cfg.DLP.OCR
		conv := dlp.DetectConverter(o.HEIFCommand, o.PDFRenderCommand, o.PDFTextCommand,
			o.PDFScaleTo, o.PDFMaxPages, o.MaxProcesses)
		dlp.SetArchiveTools(cfg.DLP.SevenZipCommand, o.MaxProcesses)
		archive := dlp.DetectArchiveTools(cfg.DLP.SevenZipCommand, 1)
		log.Info("dlp converters", "heif", orNone(conv.HEIFCmd), "pdf_render", orNone(conv.PDFToPPMCmd),
			"pdf_text", orNone(conv.PDFToTextCmd), "archive_7z", orNone(archive.SevenZip))
		combine := cfg.DLP.CombinePII == nil || *cfg.DLP.CombinePII
		scanner, err := dlp.NewScanner(dlp.Options{
			Disabled: cfg.DLP.Disabled, MinCounts: cfg.DLP.MinCounts, Rules: rules,
			ScanAttachments: cfg.DLP.ScanAttachments, Limits: dlp.DefaultLimits(), OCR: ocr,
			Converter:     conv,
			CombinePII:    combine,
			CombineMinPII: cfg.DLP.CombineMinPII,
			CombineBulk:   cfg.DLP.CombineBulk,
		})
		if err != nil {
			return err
		}
		outSvc = outbound.New(scanner, st, obj, notify.NewSMTPSender(upstreamOpts(cfg)), outbound.Options{
			Actions:                cfg.DLP.Actions,
			NotifySender:           cfg.DLP.NotifySender,
			Admins:                 cfg.DLP.Admins,
			NotifyFrom:             cfg.DLP.NotifyFrom,
			HoldTTL:                cfg.DLP.HoldTTL,
			PublicBaseURL:          cfg.Portal.PublicBaseURL,
			OwnDomains:             cfg.Outbound.SenderDomains,
			ExemptSenders:          cfg.DLP.ExemptSenders,
			ExemptRecipientDomains: cfg.DLP.ExemptRecipientDomains,
			ScanInternal:           cfg.DLP.ScanInternal,
			NextHop:                nextHopOpts(cfg),
			Location:               loc,
		}, log)
	}

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
		var spfChecker *spfutil.Checker
		if cfg.SPF.VerifyInbound {
			spfChecker = spfutil.New(nil, cfg.SPF.Timeout) // nil = system resolver
		}
		var dmarcEval *dmarc.Evaluator
		if cfg.DMARC.VerifyInbound {
			dmarcEval = dmarc.New(nil, cfg.DMARC.Timeout) // nil = system resolver
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
			VerifySPF:     cfg.SPF.VerifyInbound,
			VerifyDMARC:   cfg.DMARC.VerifyInbound,
			StripOrigDKIM: cfg.DKIM.StripOriginal,
			Signer:        signer,
			SPF:           spfChecker,
			DMARC:         dmarcEval,
		}, log)
		be := gateway.NewBackend(proc, gateway.BackendOptions{
			RecipientDomains: cfg.SMTP.AcceptedDomains,
			Upstream:         upstreamOpts(cfg),
		}, log)
		var tlsConf *tls.Config
		if cfg.SMTP.TLSCertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.SMTP.TLSCertFile, cfg.SMTP.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("smtp tls: %w", err)
			}
			tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		shut, err := startSMTP(&wg, errCh, log, smtpParams{
			name: "inbound smtp proxy", addr: cfg.SMTP.Listen, backend: be, tls: tlsConf,
			cfg: cfg, maxMessageBytes: cfg.SMTP.MaxMessageBytes,
			maxConns: cfg.SMTP.MaxConnections, perIP: cfg.SMTP.MaxConnectionsPerIP,
		})
		if err != nil {
			return err
		}
		shutdowns = append(shutdowns, shut)

		if outSvc != nil {
			clients, err := gateway.ParsePrefixes(cfg.Outbound.AllowedClients)
			if err != nil {
				return fmt.Errorf("outbound.allowed_clients: %w", err)
			}
			obe := gateway.NewBackend(outSvc, gateway.BackendOptions{
				Name:           "outbound",
				SenderDomains:  cfg.Outbound.SenderDomains,
				AllowedClients: clients,
				Upstream:       nextHopOpts(cfg),
			}, log)
			// No per-IP cap: clients are the allow-listed internal servers.
			shut, err := startSMTP(&wg, errCh, log, smtpParams{
				name: "outbound DLP listener", addr: cfg.Outbound.Listen, backend: obe, tls: tlsConf,
				cfg: cfg, maxMessageBytes: cfg.Outbound.MaxMessageBytes,
				maxConns: cfg.SMTP.MaxConnections, perIP: 0,
			})
			if err != nil {
				return err
			}
			shutdowns = append(shutdowns, shut)
		}
	}

	// ---- public portal ----
	if enabled["portal"] {
		p := portal.New(st, obj, tickets, portal.Options{
			TicketTTL:         cfg.Portal.TicketTTL,
			RateLimitRPS:      cfg.Portal.RateLimitRPS,
			RateLimitBurst:    cfg.Portal.RateLimitBurst,
			EnumPerIPBurst:    cfg.Portal.EnumPerIPBurst,
			EnumGlobalRPS:     cfg.Portal.EnumGlobalRPS,
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
			Codes:     codes,
			Mailer:    portal.NewSMTPMailer(upstreamOpts(cfg), cfg.Portal.Auth.OTPFrom),
			Holds:     holdReviewer(outSvc),
			DLPAdmins: cfg.DLP.Admins,
		}, log)
		log.Info("portal recipient authentication", "mode", cfg.Portal.Auth.Mode)
		shutdowns = append(shutdowns, serveHTTP(&wg, errCh, log, "portal", cfg.Portal.Listen, p.Handler()))
	}

	// ---- internal API for the analyzer ----
	if enabled["api"] && cfg.InternalAPI.Listen != "" {
		api := internalapi.New(st, obj, svc, cfg.InternalAPI.Token, log)
		if outSvc != nil && cfg.InternalAPI.AdminToken != "" {
			api.EnableDLPAdmin(cfg.InternalAPI.AdminToken, outSvc)
		}
		shutdowns = append(shutdowns, serveHTTP(&wg, errCh, log, "internal-api", cfg.InternalAPI.Listen, api.Handler()))
	}

	// ---- background workers ----
	if enabled["worker"] {
		wg.Add(2)
		go func() {
			defer wg.Done()
			log.Info("verdict consumer started")
			q.ConsumeResults(ctx, svc.ResultHandler())
		}()
		go func() {
			defer wg.Done()
			log.Info("janitor started", "interval", cfg.Analysis.JanitorInterval)
			svc.Janitor(ctx, cfg.Analysis.JanitorInterval)
		}()
		if outSvc != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outSvc.Janitor(ctx, cfg.Analysis.JanitorInterval)
			}()
		}
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

func orNone(s string) string {
	if s == "" {
		return "none (reported as uninspectable)"
	}
	return s
}

func nextHopOpts(cfg config.Config) smtpclient.Options {
	n := cfg.Outbound.NextHop
	if n.HeloName == "" {
		n.HeloName = cfg.SMTP.Hostname
	}
	return smtpclient.Options{Addr: n.Addr, HeloName: n.HeloName, StartTLS: n.StartTLS,
		InsecureSkipVerify: n.InsecureSkipVerify, Timeout: n.Timeout}
}

// holdReviewer avoids storing a typed nil in the interface.
func holdReviewer(s *outbound.Service) portal.HoldReviewer {
	if s == nil {
		return nil
	}
	return s
}

type smtpParams struct {
	name            string
	addr            string
	backend         smtp.Backend
	tls             *tls.Config
	cfg             config.Config
	maxMessageBytes int64
	maxConns        int
	perIP           int
}

// startSMTP configures a go-smtp server and serves it behind a connection
// limiter. It returns the server's Shutdown function.
func startSMTP(wg *sync.WaitGroup, errCh chan<- error, log *slog.Logger, p smtpParams) (func(context.Context) error, error) {
	srv := smtp.NewServer(p.backend)
	srv.Addr = p.addr
	srv.Domain = p.cfg.SMTP.Hostname
	srv.MaxMessageBytes = p.maxMessageBytes
	srv.MaxRecipients = p.cfg.SMTP.MaxRecipients
	srv.MaxLineLength = p.cfg.SMTP.MaxLineLength
	srv.ReadTimeout = p.cfg.SMTP.ReadTimeout
	srv.WriteTimeout = p.cfg.SMTP.WriteTimeout
	srv.EnableSMTPUTF8 = true
	srv.TLSConfig = p.tls

	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.name, err)
	}
	ln = gateway.NewLimitListener(ln, p.maxConns, p.perIP, log)

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info(p.name+" listening", "addr", p.addr, "max_conns", p.maxConns, "max_conns_per_ip", p.perIP)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			errCh <- fmt.Errorf("%s: %w", p.name, err)
		}
	}()
	return srv.Shutdown, nil
}

func serveHTTP(wg *sync.WaitGroup, errCh chan<- error, log *slog.Logger, name, addr string, h http.Handler) func(context.Context) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds a slow request body (e.g. a slow-POST attack)
		// without limiting response streaming, so large file downloads are
		// unaffected. WriteTimeout is deliberately unset for that reason.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
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
