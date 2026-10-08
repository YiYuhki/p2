// Package config loads the gateway configuration from a YAML file.
// Values of the form ${ENV_VAR} are expanded from the environment before
// parsing so secrets never have to be written to disk.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Timezone used for dates shown to users (banner, portal).
	Timezone    string            `yaml:"timezone"`
	SMTP        SMTPConfig        `yaml:"smtp"`
	Upstream    UpstreamConfig    `yaml:"upstream"`
	Rewrite     RewriteConfig     `yaml:"rewrite"`
	DKIM        DKIMConfig        `yaml:"dkim"`
	SPF         SPFConfig         `yaml:"spf"`
	DMARC       DMARCConfig       `yaml:"dmarc"`
	Portal      PortalConfig      `yaml:"portal"`
	InternalAPI InternalAPIConfig `yaml:"internal_api"`
	Storage     StorageConfig     `yaml:"storage"`
	Database    DatabaseConfig    `yaml:"database"`
	Redis       RedisConfig       `yaml:"redis"`
	Queue       QueueConfig       `yaml:"queue"`
	Analysis    AnalysisConfig    `yaml:"analysis"`
	Analyzer    AnalyzerConfig    `yaml:"analyzer"`
	Outbound    OutboundConfig    `yaml:"outbound"`
	DLP         DLPConfig         `yaml:"dlp"`
}

// AnalyzerConfig configures the OPTIONAL in-process attachment analyzer, which
// embeds the malengine engine and so is compiled in only when secmail is built
// with -tags malengine (the default build has no analyzer and relies on the
// external worker). It consumes jobs from the queue and applies verdicts just
// like the external worker, so it works with both the redis and memory queues.
type AnalyzerConfig struct {
	// Enabled turns the in-process analyzer on. It has no effect unless secmail
	// was built with -tags malengine.
	Enabled bool `yaml:"enabled"`
	// YaraDir is the YARA rule directory (empty: skip YARA; other static
	// detectors still run).
	YaraDir string `yaml:"yara_dir"`
	// BlockLevel is the lowest malengine verdict level mapped to MALICIOUS:
	// clean | suspicious | likely | malicious. Empty defaults to suspicious.
	BlockLevel string `yaml:"block_level"`
	// ThreatIntel enables outbound reputation lookups; Sandbox enables the
	// dynamic stage (needs Docker/Firecracker).
	ThreatIntel bool `yaml:"threat_intel"`
	Sandbox     bool `yaml:"sandbox"`
	// MaxFileSize caps the analyzed input in bytes (0: engine default).
	MaxFileSize int64 `yaml:"max_file_size"`
	// Workers is the number of concurrent analysis goroutines (0: 1).
	Workers int `yaml:"workers"`
}

// OutboundConfig enables the second SMTP listener that receives mail the
// internal server sends to the Internet, inspects it (DLP) and relays it to
// NextHop.
type OutboundConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	// AllowedClients restricts who may relay (the internal mail servers).
	AllowedClients []string `yaml:"allowed_clients"`
	// SenderDomains restricts MAIL FROM; defaults to smtp.accepted_domains.
	SenderDomains   []string       `yaml:"sender_domains"`
	NextHop         UpstreamConfig `yaml:"next_hop"`
	MaxMessageBytes int64          `yaml:"max_message_bytes"`
}

// DLP actions, from least to most strict.
const (
	ActionAllow  = "allow"  // deliver, record the event
	ActionNotify = "notify" // deliver, notify sender / admins
	ActionHold   = "hold"   // keep until an administrator releases it
	ActionBlock  = "block"  // reject; the sender receives a bounce + notice
)

type DLPActions struct {
	High          string `yaml:"high"`
	Medium        string `yaml:"medium"`
	Low           string `yaml:"low"`
	Uninspectable string `yaml:"uninspectable"` // formats that cannot be inspected
	// Encrypted applies to password-protected attachments. Empty falls back
	// to Uninspectable.
	Encrypted string `yaml:"encrypted"`
}

type DLPRule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Pattern  string   `yaml:"pattern"`
	Severity string   `yaml:"severity"`
	Category string   `yaml:"category"`
	MinCount int      `yaml:"min_count"`
	Context  []string `yaml:"context"`
}

// DLPOCRConfig enables text recognition in images (Tesseract).
type DLPOCRConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Command   string `yaml:"command"`   // default "tesseract"
	Languages string `yaml:"languages"` // default "kor+eng"
	PSM       int    `yaml:"psm"`       // page segmentation mode, default 4
	// Per message.
	MaxImages    int           `yaml:"max_images"`
	MinPixels    int           `yaml:"min_pixels"`
	Timeout      time.Duration `yaml:"timeout"`       // per image
	TotalTimeout time.Duration `yaml:"total_timeout"` // per message
	Concurrency  int           `yaml:"concurrency"`   // per message
	// MaxProcesses caps concurrent tesseract processes for the whole server.
	MaxProcesses int `yaml:"max_processes"`

	// External converters for formats Go cannot decode. Empty = auto-detect
	// on PATH, "none" = disabled (those files are reported uninspectable).
	HEIFCommand      string `yaml:"heif_command"`       // heif-dec / heif-convert (HEIC, AVIF)
	PDFRenderCommand string `yaml:"pdf_render_command"` // pdftoppm (JBIG2/JPEG2000 scans, restricted PDFs)
	PDFTextCommand   string `yaml:"pdf_text_command"`   // pdftotext (text of PDFs the Go parser rejects)
	PDFMaxPages      int    `yaml:"pdf_max_pages"`      // pages rendered per PDF
	PDFScaleTo       int    `yaml:"pdf_scale_to"`       // long side of a rendered page in pixels
}

type DLPConfig struct {
	ScanAttachments bool       `yaml:"scan_attachments"`
	Actions         DLPActions `yaml:"actions"`
	NotifySender    bool       `yaml:"notify_sender"`
	// Admins receive notices and review holds (and must be the logged-in
	// user on the review page when portal.auth is enabled).
	Admins     []string      `yaml:"admins"`
	NotifyFrom string        `yaml:"notify_from"`
	HoldTTL    time.Duration `yaml:"hold_ttl"`
	// Disabled built-in detector IDs; MinCounts overrides bulk thresholds.
	Disabled  []string       `yaml:"disabled"`
	MinCounts map[string]int `yaml:"min_counts"`
	Rules     []DLPRule      `yaml:"rules"`
	// ExemptSenders skip DLP entirely; ExemptRecipientDomains are trusted
	// partners (findings are recorded but the action is "allow").
	ExemptSenders []string     `yaml:"exempt_senders"`
	OCR           DLPOCRConfig `yaml:"ocr"`
	// ScanInternal also inspects mail whose recipients are all in our own
	// domains (off by default: only mail leaving the organisation).
	ScanInternal           bool     `yaml:"scan_internal"`
	ExemptRecipientDomains []string `yaml:"exempt_recipient_domains"`
	// CombinePII escalates a location that holds several distinct personal-data
	// types, or a bulk list, to high severity (an identity-revealing dataset
	// is riskier than an isolated value).
	CombinePII    *bool `yaml:"combine_pii"`     // default true
	CombineMinPII int   `yaml:"combine_min_pii"` // distinct PII types, default 2
	CombineBulk   int   `yaml:"combine_bulk"`    // records of one type that alone count as bulk, default 20
	// SevenZipCommand extracts 7z/RAR/xz/zstd archives ("" = auto-detect on
	// PATH, "none" = disabled). Non-encrypted archives are unpacked and their
	// contents scanned; encrypted ones follow actions.encrypted.
	SevenZipCommand string `yaml:"sevenzip_command"`
}

type SMTPConfig struct {
	Listen          string        `yaml:"listen"`
	Hostname        string        `yaml:"hostname"`
	AcceptedDomains []string      `yaml:"accepted_domains"`
	MaxMessageBytes int64         `yaml:"max_message_bytes"`
	MaxRecipients   int           `yaml:"max_recipients"`
	MaxLineLength   int           `yaml:"max_line_length"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	TLSCertFile     string        `yaml:"tls_cert_file"`
	TLSKeyFile      string        `yaml:"tls_key_file"`
	// MaxConnections caps concurrent connections on a listener (0 = unlimited).
	MaxConnections int `yaml:"max_connections"`
	// MaxConnectionsPerIP caps concurrent connections from one client IP on
	// the inbound listener (0 = unlimited). The outbound listener does not
	// apply a per-IP cap because its clients are the allow-listed internal
	// mail servers.
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip"`
}

type UpstreamConfig struct {
	Addr               string        `yaml:"addr"`
	HeloName           string        `yaml:"helo_name"`
	StartTLS           bool          `yaml:"starttls"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Timeout            time.Duration `yaml:"timeout"`
}

// Policy values for signed / encrypted messages.
const (
	PolicyRewrite     = "rewrite"
	PolicyPassthrough = "passthrough"
	PolicyReject      = "reject"
)

type RewriteConfig struct {
	// KeepInlineImages keeps image/* parts carrying a Content-ID inside
	// multipart/related (images embedded in HTML bodies).
	KeepInlineImages bool `yaml:"keep_inline_images"`
	// SignedPolicy: rewrite (strip attachments, signature breaks) | passthrough.
	SignedPolicy string `yaml:"signed_policy"`
	// EncryptedPolicy: passthrough | reject. Encrypted content cannot be inspected.
	EncryptedPolicy string `yaml:"encrypted_policy"`
	// GatewayID is stamped into X-SecMail-* headers.
	GatewayID string `yaml:"gateway_id"`
	// BlockedExtensions are inbound attachment file extensions refused up front
	// (marked blocked without analysis; the portal never releases them). Matched
	// on the final extension, e.g. "exe", "scr", "js".
	BlockedExtensions []string `yaml:"blocked_extensions"`
}

// SPFConfig controls inbound SPF verification. The result is added to
// Authentication-Results alongside DKIM so downstream DMARC has both inputs.
type SPFConfig struct {
	VerifyInbound bool          `yaml:"verify_inbound"`
	Timeout       time.Duration `yaml:"timeout"` // per-message DNS budget (default 10s)
}

// DMARCConfig controls inbound DMARC evaluation. The verdict (dmarc=pass/fail)
// is added to Authentication-Results; the gateway does not reject on it
// (enforcement is left to the internal mail server's policy). Requires SPF
// and/or DKIM verification to be enabled to have inputs to align.
type DMARCConfig struct {
	VerifyInbound bool          `yaml:"verify_inbound"`
	Timeout       time.Duration `yaml:"timeout"` // DNS budget for the policy lookup (default 5s)
}

type DKIMConfig struct {
	VerifyInbound  bool   `yaml:"verify_inbound"`
	StripOriginal  bool   `yaml:"strip_original"`
	Sign           bool   `yaml:"sign"`
	Domain         string `yaml:"domain"`
	Selector       string `yaml:"selector"`
	PrivateKeyFile string `yaml:"private_key_file"`
}

type PortalConfig struct {
	Listen         string        `yaml:"listen"`
	PublicBaseURL  string        `yaml:"public_base_url"`
	LinkTTL        time.Duration `yaml:"link_ttl"`
	TicketTTL      time.Duration `yaml:"ticket_ttl"`
	RateLimitRPS   float64       `yaml:"rate_limit_rps"`
	RateLimitBurst int           `yaml:"rate_limit_burst"`
	// EnumPerIPBurst is how many missed (unknown/malformed) token lookups a
	// single client may make before it is throttled; EnumGlobalRPS caps the
	// aggregate miss rate across all clients (defends distributed guessing).
	EnumPerIPBurst int     `yaml:"enum_per_ip_burst"`
	EnumGlobalRPS  float64 `yaml:"enum_global_rps"`
	// TrustProxyHeaders makes the rate limiter key on X-Forwarded-For.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
	// TLSCertFile / TLSKeyFile enable HTTPS on the portal listener directly
	// (no reverse proxy). Empty serves plain HTTP (e.g. behind a TLS proxy).
	TLSCertFile string           `yaml:"tls_cert_file"`
	TLSKeyFile  string           `yaml:"tls_key_file"`
	Auth        PortalAuthConfig `yaml:"auth"`
}

// Recipient authentication modes for the download portal.
const (
	AuthNone   = "none"   // possession of the link is enough
	AuthOTP    = "otp"    // one-time code mailed to a recipient address
	AuthHeader = "header" // identity asserted by an SSO reverse proxy header
)

type PortalAuthConfig struct {
	Mode string `yaml:"mode"`
	// SessionSecret signs the session cookie (otp mode), >= 32 chars.
	SessionSecret string        `yaml:"session_secret"`
	SessionTTL    time.Duration `yaml:"session_ttl"`
	// AllowDomainUsers lets any address in smtp.accepted_domains open the
	// link, not only the envelope recipients. Needed when mail is addressed
	// to distribution lists / aliases.
	AllowDomainUsers bool `yaml:"allow_domain_users"`
	// TrustedHeader carries the user's e-mail in header mode, e.g.
	// X-Auth-Request-Email (oauth2-proxy) or X-Forwarded-Email.
	TrustedHeader string `yaml:"trusted_header"`
	// OTP settings.
	OTPTTL         time.Duration `yaml:"otp_ttl"`
	OTPMaxAttempts int           `yaml:"otp_max_attempts"`
	OTPResendAfter time.Duration `yaml:"otp_resend_after"`
	OTPFrom        string        `yaml:"otp_from"`
}

type InternalAPIConfig struct {
	Listen string `yaml:"listen"`
	Token  string `yaml:"token"`
	// AdvertiseURL is the base URL analyzers use to reach this API; it is
	// embedded in every job (content_url / verdict_url). Optional.
	AdvertiseURL string `yaml:"advertise_url"`
	// AdminToken protects the DLP administration endpoints
	// (/internal/v1/dlp/*). Empty disables them.
	AdminToken string `yaml:"admin_token"`
}

type StorageConfig struct {
	Type string   `yaml:"type"` // s3 | fs
	S3   S3Config `yaml:"s3"`
	FS   FSConfig `yaml:"fs"`
}

type S3Config struct {
	Endpoint  string `yaml:"endpoint"`
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	UseSSL    bool   `yaml:"use_ssl"`
}

type FSConfig struct {
	Dir string `yaml:"dir"`
}

type DatabaseConfig struct {
	Type string `yaml:"type"` // postgres | memory
	DSN  string `yaml:"dsn"`
	// Connection pool tuning (0 = pgx default; DSN pool params still apply).
	MaxConns        int32         `yaml:"max_conns"`
	MinConns        int32         `yaml:"min_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	// PoolSize caps connections per instance (0 = go-redis default, 10×CPU).
	PoolSize int `yaml:"pool_size"`
}

type QueueConfig struct {
	Type      string `yaml:"type"` // redis | memory
	KeyPrefix string `yaml:"key_prefix"`
}

type AnalysisConfig struct {
	// Timeout after which a PENDING attachment is re-queued.
	Timeout time.Duration `yaml:"timeout"`
	// MaxAttempts before the attachment is marked ERROR (download blocked).
	MaxAttempts int `yaml:"max_attempts"`
	// VerdictReuseWindow reuses a verdict for an identical SHA-256 seen within
	// the window. Zero disables reuse.
	VerdictReuseWindow time.Duration `yaml:"verdict_reuse_window"`
	// JanitorInterval controls the expiry / stale-job sweep.
	JanitorInterval time.Duration `yaml:"janitor_interval"`
	// AuditRetention, when > 0, makes the janitor delete dlp_events and
	// download_events older than this. 0 (default) keeps the audit log forever.
	AuditRetention time.Duration `yaml:"audit_retention"`
}

func Default() Config {
	return Config{
		Timezone: "Asia/Seoul",
		SMTP: SMTPConfig{
			Listen:              ":2525",
			Hostname:            "localhost",
			MaxMessageBytes:     50 << 20,
			MaxRecipients:       100,
			MaxLineLength:       2000,
			ReadTimeout:         60 * time.Second,
			WriteTimeout:        60 * time.Second,
			MaxConnections:      1024,
			MaxConnectionsPerIP: 50,
		},
		Upstream: UpstreamConfig{Timeout: 60 * time.Second},
		Rewrite: RewriteConfig{
			KeepInlineImages: true,
			SignedPolicy:     PolicyRewrite,
			EncryptedPolicy:  PolicyPassthrough,
			GatewayID:        "secmail",
		},
		DKIM:  DKIMConfig{StripOriginal: true},
		SPF:   SPFConfig{Timeout: 10 * time.Second},
		DMARC: DMARCConfig{Timeout: 5 * time.Second},
		Portal: PortalConfig{
			Listen:         ":8080",
			PublicBaseURL:  "http://localhost:8080",
			LinkTTL:        14 * 24 * time.Hour,
			TicketTTL:      60 * time.Second,
			RateLimitRPS:   5,
			RateLimitBurst: 20,
			EnumPerIPBurst: 10,
			EnumGlobalRPS:  20,
			Auth: PortalAuthConfig{
				Mode:           AuthNone,
				SessionTTL:     12 * time.Hour,
				OTPTTL:         10 * time.Minute,
				OTPMaxAttempts: 5,
				OTPResendAfter: time.Minute,
			},
		},
		InternalAPI: InternalAPIConfig{Listen: "127.0.0.1:8081"},
		Storage:     StorageConfig{Type: "fs", FS: FSConfig{Dir: "./data/objects"}},
		Database:    DatabaseConfig{Type: "memory", MaxConns: 20, MinConns: 2, ConnMaxLifetime: 30 * time.Minute},
		Redis:       RedisConfig{Addr: "localhost:6379"},
		Queue:       QueueConfig{Type: "memory", KeyPrefix: "secmail"},
		Outbound: OutboundConfig{Listen: ":10025", MaxMessageBytes: 50 << 20,
			NextHop: UpstreamConfig{Timeout: 60 * time.Second}},
		DLP: DLPConfig{
			ScanAttachments: true,
			Actions: DLPActions{High: ActionHold, Medium: ActionNotify, Low: ActionAllow,
				Uninspectable: ActionNotify, Encrypted: ActionHold},
			NotifySender:  true,
			HoldTTL:       72 * time.Hour,
			CombineMinPII: 2,
			CombineBulk:   20,
			OCR: DLPOCRConfig{Command: "tesseract", Languages: "kor+eng", PSM: 4, MaxImages: 20,
				MinPixels: 150 * 60, Timeout: 20 * time.Second, TotalTimeout: 60 * time.Second,
				Concurrency: 2, MaxProcesses: 4, PDFMaxPages: 10, PDFScaleTo: 2400},
		},
		Analysis: AnalysisConfig{
			Timeout:            5 * time.Minute,
			MaxAttempts:        3,
			VerdictReuseWindow: 24 * time.Hour,
			JanitorInterval:    time.Minute,
		},
	}
}

// Load reads path (if non-empty) over the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		expanded := os.ExpandEnv(string(raw))
		if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	var errs []error
	if c.Upstream.Addr == "" {
		errs = append(errs, errors.New("upstream.addr is required"))
	}
	if len(c.SMTP.AcceptedDomains) == 0 {
		errs = append(errs, errors.New("smtp.accepted_domains must not be empty (open relay protection)"))
	}
	if c.DMARC.VerifyInbound && !c.SPF.VerifyInbound && !c.DKIM.VerifyInbound {
		errs = append(errs, errors.New("dmarc.verify_inbound requires spf.verify_inbound and/or dkim.verify_inbound"))
	}
	for i, d := range c.SMTP.AcceptedDomains {
		c.SMTP.AcceptedDomains[i] = strings.ToLower(strings.TrimSpace(d))
	}
	if (c.SMTP.TLSCertFile == "") != (c.SMTP.TLSKeyFile == "") {
		errs = append(errs, errors.New("smtp.tls_cert_file and smtp.tls_key_file must be set together"))
	}
	if (c.Portal.TLSCertFile == "") != (c.Portal.TLSKeyFile == "") {
		errs = append(errs, errors.New("portal.tls_cert_file and portal.tls_key_file must be set together"))
	}
	c.Portal.PublicBaseURL = strings.TrimRight(c.Portal.PublicBaseURL, "/")
	c.InternalAPI.AdvertiseURL = strings.TrimRight(c.InternalAPI.AdvertiseURL, "/")
	switch c.Rewrite.SignedPolicy {
	case PolicyRewrite, PolicyPassthrough:
	default:
		errs = append(errs, fmt.Errorf("rewrite.signed_policy: unknown value %q", c.Rewrite.SignedPolicy))
	}
	switch c.Rewrite.EncryptedPolicy {
	case PolicyPassthrough, PolicyReject:
	default:
		errs = append(errs, fmt.Errorf("rewrite.encrypted_policy: unknown value %q", c.Rewrite.EncryptedPolicy))
	}
	switch a := c.Portal.Auth; a.Mode {
	case AuthNone:
	case AuthOTP:
		if len(a.SessionSecret) < 32 {
			errs = append(errs, errors.New("portal.auth.session_secret must be at least 32 characters"))
		}
		if a.OTPFrom == "" {
			errs = append(errs, errors.New("portal.auth.otp_from is required in otp mode"))
		}
	case AuthHeader:
		if a.TrustedHeader == "" {
			errs = append(errs, errors.New("portal.auth.trusted_header is required in header mode"))
		}
	default:
		errs = append(errs, fmt.Errorf("portal.auth.mode: unknown value %q", a.Mode))
	}
	if c.Outbound.Enabled {
		if c.Outbound.NextHop.Addr == "" {
			errs = append(errs, errors.New("outbound.next_hop.addr is required"))
		}
		if len(c.Outbound.AllowedClients) == 0 {
			errs = append(errs, errors.New("outbound.allowed_clients must list the internal mail servers (open relay protection)"))
		}
		if len(c.Outbound.SenderDomains) == 0 {
			c.Outbound.SenderDomains = append([]string(nil), c.SMTP.AcceptedDomains...)
		}
		for i, d := range c.Outbound.SenderDomains {
			c.Outbound.SenderDomains[i] = strings.ToLower(strings.TrimSpace(d))
		}
		if c.DLP.Actions.Encrypted == "" {
			c.DLP.Actions.Encrypted = c.DLP.Actions.Uninspectable
		}
		a := c.DLP.Actions
		for name, v := range map[string]string{"high": a.High, "medium": a.Medium, "low": a.Low,
			"uninspectable": a.Uninspectable, "encrypted": a.Encrypted} {
			switch v {
			case ActionAllow, ActionNotify, ActionHold, ActionBlock:
			default:
				errs = append(errs, fmt.Errorf("dlp.actions.%s: unknown action %q", name, v))
			}
		}
		if c.DLP.NotifyFrom == "" && (c.DLP.NotifySender || len(c.DLP.Admins) > 0) {
			errs = append(errs, errors.New("dlp.notify_from is required for notifications"))
		}
		if (a.High == ActionHold || a.Medium == ActionHold || a.Low == ActionHold ||
			a.Uninspectable == ActionHold || a.Encrypted == ActionHold) && len(c.DLP.Admins) == 0 {
			errs = append(errs, errors.New("dlp.admins is required when an action is \"hold\""))
		}
	}
	if c.DKIM.Sign && (c.DKIM.Domain == "" || c.DKIM.Selector == "" || c.DKIM.PrivateKeyFile == "") {
		errs = append(errs, errors.New("dkim.sign requires domain, selector and private_key_file"))
	}
	if c.InternalAPI.Listen != "" && len(c.InternalAPI.Token) < 16 {
		errs = append(errs, errors.New("internal_api.token must be at least 16 characters"))
	}
	if c.InternalAPI.AdminToken != "" && len(c.InternalAPI.AdminToken) < 16 {
		errs = append(errs, errors.New("internal_api.admin_token must be at least 16 characters"))
	}
	if c.InternalAPI.AdminToken != "" && c.InternalAPI.AdminToken == c.InternalAPI.Token {
		errs = append(errs, errors.New("internal_api.admin_token must differ from internal_api.token"))
	}
	if c.Analysis.MaxAttempts < 1 {
		c.Analysis.MaxAttempts = 1
	}
	return errors.Join(errs...)
}
