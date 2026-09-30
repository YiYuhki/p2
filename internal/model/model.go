// Package model holds the domain types shared across the gateway.
package model

import (
	"encoding/json"
	"time"
)

type Status string

const (
	// StatusPending: stored and queued, verdict not available yet.
	StatusPending Status = "PENDING"
	// StatusClean: analyzer found nothing; download allowed.
	StatusClean Status = "CLEAN"
	// StatusMalicious: analyzer flagged the file; download blocked.
	StatusMalicious Status = "MALICIOUS"
	// StatusError: analysis failed permanently; download blocked (fail closed).
	StatusError Status = "ERROR"
	// StatusExpired: link TTL elapsed and the object was deleted.
	StatusExpired Status = "EXPIRED"
)

func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusClean, StatusMalicious, StatusError, StatusExpired:
		return true
	}
	return false
}

// Final reports whether s is an analyzer verdict (terminal for analysis).
func (s Status) Final() bool {
	return s == StatusClean || s == StatusMalicious || s == StatusError
}

// Message is the envelope/metadata record of a processed mail.
type Message struct {
	ID              string
	MessageID       string // RFC 5322 Message-ID header
	MailFrom        string
	RcptTo          []string
	Subject         string
	RemoteAddr      string
	ReceivedAt      time.Time
	AttachmentCount int
}

// Attachment is an attachment removed from a message and held in quarantine.
type Attachment struct {
	ID          string
	MessageID   string // references Message.ID
	Filename    string
	ContentType string
	Size        int64
	SHA256      string
	StorageKey  string
	TokenHash   string

	Status        Status
	ThreatName    string
	VerdictDetail json.RawMessage
	Attempts      int

	CreatedAt        time.Time
	UpdatedAt        time.Time
	QueuedAt         time.Time
	AnalyzedAt       *time.Time
	ExpiresAt        time.Time
	DownloadCount    int
	LastDownloadedAt *time.Time
}

// DownloadEvent is an audit record of a completed download.
type DownloadEvent struct {
	AttachmentID string
	User         string // authenticated recipient address, "" when auth is off
	RemoteIP     string
	UserAgent    string
	At           time.Time
}

// Verdict is what the external analyzer reports back.
type Verdict struct {
	AttachmentID string          `json:"attachment_id"`
	Status       Status          `json:"status"`
	ThreatName   string          `json:"threat_name,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`
}

// Job is the unit of work published to the analysis queue. It is the
// contract with the external analysis project (see docs/analyzer-contract.md).
type Job struct {
	Version      int       `json:"version"`
	AttachmentID string    `json:"attachment_id"`
	MessageID    string    `json:"message_id"`
	Filename     string    `json:"filename"`
	ContentType  string    `json:"content_type"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	Storage      JobObject `json:"storage"`
	ContentURL   string    `json:"content_url,omitempty"`
	VerdictURL   string    `json:"verdict_url,omitempty"`
	Attempt      int       `json:"attempt"`
	EnqueuedAt   time.Time `json:"enqueued_at"`
}

type JobObject struct {
	Type   string `json:"type"` // s3 | fs
	Bucket string `json:"bucket,omitempty"`
	Key    string `json:"key"`
}

// ---- outbound DLP ----

type HoldStatus string

const (
	HoldHeld     HoldStatus = "HELD"     // waiting for an administrator
	HoldReleased HoldStatus = "RELEASED" // approved and relayed
	HoldRejected HoldStatus = "REJECTED" // refused by an administrator
	HoldExpired  HoldStatus = "EXPIRED"  // not decided within hold_ttl (not sent)
)

// Hold is an outgoing message withheld by DLP policy pending review.
type Hold struct {
	ID         string
	TokenHash  string // review-link token (hash)
	MailFrom   string
	RcptTo     []string
	Subject    string
	StorageKey string
	Size       int64
	Findings   json.RawMessage // dlp.Report
	Status     HoldStatus
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DecidedAt  *time.Time
	DecidedBy  string
	Reason     string
}

// DLPEvent is the audit record of an outbound message with findings.
type DLPEvent struct {
	ID       string
	MailFrom string
	RcptTo   []string
	Subject  string
	Action   string // allow | notify | hold | block
	Severity string
	Findings json.RawMessage
	HoldID   string
	At       time.Time
}
