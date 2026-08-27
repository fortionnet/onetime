// Package crypto implements the storage format for onetime secrets.
//
// The design in one paragraph: every secret is addressed by a 32-byte random
// Key that lives only in the URL fragment and is never persisted. The Redis key
// is a hash of it, and the encryption key is derived from it together with the
// server's master keyring (and the passphrase, if any). A dump of Redis and the
// master key together therefore decrypt nothing — the Key is missing.
//
// Every type in this package that holds secret material redacts itself in logs,
// in fmt verbs and in JSON. That is deliberate belt-and-braces: the JSON
// redaction exists so that accidentally serialising a request DTO into an error
// response cannot leak plaintext.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
)

const (
	// KeyLen is the size of the fragment key in bytes. 256 bits of entropy puts
	// enumeration out of reach, which is why we can afford to tell a visitor
	// whether a link was already read rather than lumping every failure into a
	// single indistinguishable 404.
	KeyLen = 32
	// IDLen is how many base64 characters of the key hash address a record.
	IDLen = 22

	domainSecretID  = "onetime-id-v1"
	domainReceiptID = "onetime-mid-v1"
	domainTicketID  = "onetime-tid-v1"

	redacted = "[REDACTED]"
)

var (
	// ErrBadKey means the input was not a syntactically valid key. Rejecting it
	// here keeps malformed input from ever reaching Redis.
	ErrBadKey = errors.New("crypto: malformed key")
	// ErrBadPassphrase means the DEK could not be unwrapped: either the
	// passphrase is wrong, the key is wrong, or the stored record was tampered
	// with. The three are indistinguishable by design.
	ErrBadPassphrase = errors.New("crypto: cannot unwrap data key")
)

var b64 = base64.RawURLEncoding

// Key is the per-secret random value carried in the URL fragment.
type Key [KeyLen]byte

// NewKey returns a fresh random key.
func NewKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("crypto: generate key: %w", err)
	}
	return k, nil
}

// ParseKey decodes a key from its base64url form, rejecting anything of the
// wrong length or alphabet.
func ParseKey(s string) (Key, error) {
	if len(s) != b64.EncodedLen(KeyLen) {
		return Key{}, ErrBadKey
	}
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != KeyLen {
		return Key{}, ErrBadKey
	}
	var k Key
	copy(k[:], raw)
	return k, nil
}

// Encode returns the base64url form. This is the only way to get the raw value
// out of a Key, so every place that exposes one is greppable.
func (k Key) Encode() string { return b64.EncodeToString(k[:]) }

// SecretID is the Redis key under which the secret record is stored.
func (k Key) SecretID() string { return derivedID(domainSecretID, k[:]) }

// ReceiptID is the Redis key for the sender's receipt record.
func (k Key) ReceiptID() string { return derivedID(domainReceiptID, k[:]) }

// Equal reports whether two keys match, in constant time.
func (k Key) Equal(other Key) bool { return subtle.ConstantTimeCompare(k[:], other[:]) == 1 }

func (Key) String() string               { return redacted }
func (Key) GoString() string             { return redacted }
func (Key) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Key) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Key) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Ticket authorises a single file download after the secret has already been
// burned. It carries the data key inside itself rather than in Redis, so a dump
// taken during the ticket's five-minute life is still worthless.
type Ticket struct {
	Nonce [16]byte
	DEK   DEK
}

// NewTicket mints a download ticket for an already-unwrapped data key.
func NewTicket(dek DEK) (Ticket, error) {
	var t Ticket
	if _, err := rand.Read(t.Nonce[:]); err != nil {
		return Ticket{}, fmt.Errorf("crypto: generate ticket: %w", err)
	}
	t.DEK = dek
	return t, nil
}

// ParseTicket decodes a ticket from its base64url form.
func ParseTicket(s string) (Ticket, error) {
	if len(s) != b64.EncodedLen(16+DEKLen) {
		return Ticket{}, ErrBadKey
	}
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != 16+DEKLen {
		return Ticket{}, ErrBadKey
	}
	var t Ticket
	copy(t.Nonce[:], raw[:16])
	copy(t.DEK[:], raw[16:])
	return t, nil
}

// Encode returns the base64url form of the ticket.
func (t Ticket) Encode() string {
	buf := make([]byte, 0, 16+DEKLen)
	buf = append(buf, t.Nonce[:]...)
	buf = append(buf, t.DEK[:]...)
	return b64.EncodeToString(buf)
}

// ID is the Redis key for the ticket record. It is derived from the nonce only,
// so the stored record never reveals anything about the data key.
func (t Ticket) ID() string { return derivedID(domainTicketID, t.Nonce[:]) }

func (Ticket) String() string               { return redacted }
func (Ticket) GoString() string             { return redacted }
func (Ticket) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Ticket) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Passphrase is an optional low-entropy secret supplied by the user. It is
// never stored, not even as a hash: it is verified by whether the AEAD tag on
// the wrapped data key authenticates.
type Passphrase []byte

// Empty reports whether no passphrase was supplied.
func (p Passphrase) Empty() bool { return len(p) == 0 }

func (Passphrase) String() string               { return redacted }
func (Passphrase) GoString() string             { return redacted }
func (Passphrase) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Passphrase) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Plaintext is decrypted user content on its way to the response writer.
type Plaintext []byte

func (Plaintext) String() string               { return redacted }
func (Plaintext) GoString() string             { return redacted }
func (Plaintext) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Plaintext) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

func derivedID(domain string, material []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(material)
	return b64.EncodeToString(h.Sum(nil))[:IDLen]
}
