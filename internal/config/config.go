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
	Portal      PortalConfig      `yaml:"portal"`
	InternalAPI InternalAPIConfig `yaml:"internal_api"`
	Storage     StorageConfig     `yaml:"storage"`
	Database    DatabaseConfig    `yaml:"database"`
	Redis       RedisConfig       `yaml:"redis"`
	Queue       QueueConfig       `yaml:"queue"`
	Analysis    AnalysisConfig    `yaml:"analysis"`
}

type SMTPConfig struct {
	Listen          string        `yaml:"listen"`
	Hostname        string        `yaml:"hostname"`
	AcceptedDomains []string      `yaml:"accepted_domains"`
	MaxMessageBytes int64         `yaml:"max_message_bytes"`
	MaxRecipients   int           `yaml:"max_recipients"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	TLSCertFile     string        `yaml:"tls_cert_file"`
	TLSKeyFile      string        `yaml:"tls_key_file"`
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
	// TrustProxyHeaders makes the rate limiter key on X-Forwarded-For.
	TrustProxyHeaders bool             `yaml:"trust_proxy_headers"`
	Auth              PortalAuthConfig `yaml:"auth"`
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
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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
}

func Default() Config {
	return Config{
		Timezone: "Asia/Seoul",
		SMTP: SMTPConfig{
			Listen:          ":2525",
			Hostname:        "localhost",
			MaxMessageBytes: 50 << 20,
			MaxRecipients:   100,
			ReadTimeout:     60 * time.Second,
			WriteTimeout:    60 * time.Second,
		},
		Upstream: UpstreamConfig{Timeout: 60 * time.Second},
		Rewrite: RewriteConfig{
			KeepInlineImages: true,
			SignedPolicy:     PolicyRewrite,
			EncryptedPolicy:  PolicyPassthrough,
			GatewayID:        "secmail",
		},
		DKIM: DKIMConfig{StripOriginal: true},
		Portal: PortalConfig{
			Listen:         ":8080",
			PublicBaseURL:  "http://localhost:8080",
			LinkTTL:        14 * 24 * time.Hour,
			TicketTTL:      60 * time.Second,
			RateLimitRPS:   5,
			RateLimitBurst: 20,
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
		Database:    DatabaseConfig{Type: "memory"},
		Redis:       RedisConfig{Addr: "localhost:6379"},
		Queue:       QueueConfig{Type: "memory", KeyPrefix: "secmail"},
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
	for i, d := range c.SMTP.AcceptedDomains {
		c.SMTP.AcceptedDomains[i] = strings.ToLower(strings.TrimSpace(d))
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
	if c.DKIM.Sign && (c.DKIM.Domain == "" || c.DKIM.Selector == "" || c.DKIM.PrivateKeyFile == "") {
		errs = append(errs, errors.New("dkim.sign requires domain, selector and private_key_file"))
	}
	if c.InternalAPI.Listen != "" && len(c.InternalAPI.Token) < 16 {
		errs = append(errs, errors.New("internal_api.token must be at least 16 characters"))
	}
	if c.Analysis.MaxAttempts < 1 {
		c.Analysis.MaxAttempts = 1
	}
	return errors.Join(errs...)
}
