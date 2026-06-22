package storage

import (
	"net/mail"
	"time"
)

// Message data excluding physical attachments
//
// swagger:model Message
type Message struct {
	ID string
	MessageID string
	From *mail.Address
	To []*mail.Address
	Cc []*mail.Address
	Bcc []*mail.Address
	ReplyTo []*mail.Address
	ReturnPath string
	Subject string
	ListUnsubscribe ListUnsubscribe
	Date time.Time
	Tags []string
	Username string
	Text string
	HTML string
	Size uint64
	Inline []Attachment
	Attachments []Attachment
	DKIMStatus string
	AttachmentSizeWarning bool
}

// Attachment struct for inline images and attachments
//
// swagger:model Attachment
type Attachment struct {
	// Attachment part ID
	PartID string
	// File name
	FileName string
	// Content type
	ContentType string
	// Content ID
	ContentID string
	// Size in bytes
	Size uint64
	// File checksums
	Checksums struct {
		// MD5 checksum hash of file
		MD5 string
		// SHA1 checksum hash of file
		SHA1 string
		// SHA256 checksum hash of file
		SHA256 string
	}
}

// MessageSummary struct for frontend messages
//
// swagger:model MessageSummary
type MessageSummary struct {
	// Database ID
	ID string
	// Message ID
	MessageID string
	// Read status
	Read bool
	// From address
	From *mail.Address
	// To address
	To []*mail.Address
	// Cc addresses
	Cc []*mail.Address
	// Bcc addresses
	Bcc []*mail.Address
	// Reply-To address
	ReplyTo []*mail.Address
	// Email subject
	Subject string
	// Received RFC3339Nano date & time ([extended RFC3339](https://tools.ietf.org/html/rfc3339#section-5.6) format with optional nano seconds)
	Created time.Time
	// Username used for authentication (if provided) with the SMTP or Send API
	Username string
	// Message tags
	Tags []string
	// Message size in bytes (total)
	Size uint64
	// Whether the message has any attachments
	Attachments int
	// Message snippet includes up to 250 characters
	Snippet string
}

// MailboxStats struct for quick mailbox total/read lookups
type MailboxStats struct {
	Total  uint64
	Unread uint64
	Tags   []string
}

// Metadata struct for storing message metadata
type Metadata struct {
	From     *mail.Address   `json:"From,omitempty"`
	To       []*mail.Address `json:"To,omitempty"`
	Cc       []*mail.Address `json:"Cc,omitempty"`
	Bcc      []*mail.Address `json:"Bcc,omitempty"`
	ReplyTo  []*mail.Address `json:"ReplyTo,omitempty"`
	Username string          `json:"Username,omitempty"`
}

// ListUnsubscribe contains a summary of List-Unsubscribe & List-Unsubscribe-Post headers
// including validation of the link structure
type ListUnsubscribe struct {
	// List-Unsubscribe header value
	Header string
	// Detected links, maximum one email and one HTTP(S) link
	Links []string
	// Validation errors (if any)
	Errors string
	// List-Unsubscribe-Post value (if set)
	HeaderPost string
}
