package store

import (
	"errors"
	"strconv"
	"time"
)

// Record states. A consumed or burned record is not deleted outright: it leaves
// a tombstone carrying only its state and timestamps. That is what lets the UI
// say "someone already opened this" instead of "no such link" — a real
// difference to the recipient, and one that gives an attacker nothing, since
// guessing an id means guessing 256 bits.
const (
	StateNew       = "new"
	StateConsumed  = "consumed"
	StateBurned    = "burned"
	StateDestroyed = "destroyed"
)

// Kinds of payload.
const (
	KindText = "text"
	KindFile = "file"
)

// AlgV1 is the only storage format in use: HKDF/Argon2id key derivation with an
// AES-256-GCM STREAM payload.
const AlgV1 = "a1"

// Secret record field names.
const (
	fVersion    = "v"
	fState      = "state"
	fKind       = "kind"
	fAlg        = "alg"
	fKeyID      = "kid"
	fSalt       = "salt"
	fKDFParams  = "kdfp"
	fWrappedDEK = "wdek"
	fHasPass    = "haspw"
	fCiphertext = "ct"
	fBlob       = "blob"
	fMetaCT     = "meta_ct"
	fPlainSize  = "psize"
	fEncSize    = "esize"
	fReceiptID  = "mid"
	fCreated    = "created"
	fExpires    = "expires"
	fConsumedAt = "consumed_at"

	// Receipt-only fields.
	fSecretID      = "sid"
	fPeekedAt      = "peeked_at"
	fPassFails     = "pw_fails"
	fSecretExpires = "secret_expires"

	// Ticket-only fields.
	fFilenameCT = "fname_ct"
	fPayloadAAD = "aad"
	fAttempts   = "attempts"
)

// ErrNotFound means no record exists for the given id.
var ErrNotFound = errors.New("store: record not found")

// Secret is a stored secret record. Payload holds inline ciphertext for short
// text; larger text and every file live in Blob on the volume instead.
type Secret struct {
	Version    int
	State      string
	Kind       string
	Alg        string
	KeyID      string
	Salt       []byte
	KDFParams  string
	WrappedDEK []byte
	HasPass    bool
	Payload    []byte
	Blob       string
	MetaCT     []byte
	PlainSize  int64
	EncSize    int64
	ReceiptID  string
	Created    time.Time
	Expires    time.Time
	ConsumedAt time.Time
}

func (s *Secret) toMap() map[string]any {
	m := map[string]any{
		fVersion:    1,
		fState:      s.State,
		fKind:       s.Kind,
		fAlg:        s.Alg,
		fKeyID:      s.KeyID,
		fSalt:       s.Salt,
		fWrappedDEK: s.WrappedDEK,
		fHasPass:    boolToInt(s.HasPass),
		fPlainSize:  s.PlainSize,
		fEncSize:    s.EncSize,
		fReceiptID:  s.ReceiptID,
		fCreated:    s.Created.Unix(),
		fExpires:    s.Expires.Unix(),
	}
	if s.KDFParams != "" {
		m[fKDFParams] = s.KDFParams
	}
	if len(s.Payload) > 0 {
		m[fCiphertext] = s.Payload
	}
	if s.Blob != "" {
		m[fBlob] = s.Blob
	}
	if len(s.MetaCT) > 0 {
		m[fMetaCT] = s.MetaCT
	}
	return m
}

func secretFromMap(m map[string]string) *Secret {
	return &Secret{
		Version:    atoiOr(m[fVersion], 0),
		State:      m[fState],
		Kind:       m[fKind],
		Alg:        m[fAlg],
		KeyID:      m[fKeyID],
		Salt:       []byte(m[fSalt]),
		KDFParams:  m[fKDFParams],
		WrappedDEK: []byte(m[fWrappedDEK]),
		HasPass:    m[fHasPass] == "1",
		Payload:    []byte(m[fCiphertext]),
		Blob:       m[fBlob],
		MetaCT:     []byte(m[fMetaCT]),
		PlainSize:  atoi64Or(m[fPlainSize], 0),
		EncSize:    atoi64Or(m[fEncSize], 0),
		ReceiptID:  m[fReceiptID],
		Created:    unixOrZero(m[fCreated]),
		Expires:    unixOrZero(m[fExpires]),
		ConsumedAt: unixOrZero(m[fConsumedAt]),
	}
}

// Receipt is the sender's private record. It outlives the secret so that the
// sender can still see what happened after the recipient read it.
//
// It carries the secret's id, which is enough to invalidate the secret but not
// to read it: decryption needs the fragment key, which only the recipient link
// contains. That is a deliberate departure from the reference implementation,
// where the sender can re-read their own secret from the receipt page.
type Receipt struct {
	Version       int
	State         string
	Kind          string
	SecretID      string
	HasPass       bool
	PlainSize     int64
	Created       time.Time
	SecretExpires time.Time
	Expires       time.Time
	PeekedAt      time.Time
	ConsumedAt    time.Time
	PassFails     int
}

func (r *Receipt) toMap() map[string]any {
	return map[string]any{
		fVersion:       1,
		fState:         r.State,
		fKind:          r.Kind,
		fSecretID:      r.SecretID,
		fHasPass:       boolToInt(r.HasPass),
		fPlainSize:     r.PlainSize,
		fCreated:       r.Created.Unix(),
		fSecretExpires: r.SecretExpires.Unix(),
		fExpires:       r.Expires.Unix(),
	}
}

func receiptFromMap(m map[string]string) *Receipt {
	return &Receipt{
		Version:       atoiOr(m[fVersion], 0),
		State:         m[fState],
		Kind:          m[fKind],
		SecretID:      m[fSecretID],
		HasPass:       m[fHasPass] == "1",
		PlainSize:     atoi64Or(m[fPlainSize], 0),
		Created:       unixOrZero(m[fCreated]),
		SecretExpires: unixOrZero(m[fSecretExpires]),
		Expires:       unixOrZero(m[fExpires]),
		PeekedAt:      unixOrZero(m[fPeekedAt]),
		ConsumedAt:    unixOrZero(m[fConsumedAt]),
		PassFails:     atoiOr(m[fPassFails], 0),
	}
}

// Ticket authorises downloading one already-revealed file.
//
// PayloadAAD is the associated data the blob was sealed under. It has to
// travel with the ticket because the download path no longer has the secret
// record to derive it from, and it is not secret — it only binds the payload to
// the record it came from.
type Ticket struct {
	Blob       string
	FilenameCT []byte
	PayloadAAD []byte
	PlainSize  int64
}

// Claim is the outcome of trying to consume a secret.
type Claim struct {
	// Won is true for exactly one caller, even under concurrent reveals.
	Won bool
	// State is the state observed when the claim lost, for a useful message.
	State string
	// Found is false when no record exists at all.
	Found     bool
	Kind      string
	Payload   []byte
	Blob      string
	MetaCT    []byte
	PlainSize int64
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func atoi64Or(s string, def int64) int64 {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return def
}

func unixOrZero(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}
