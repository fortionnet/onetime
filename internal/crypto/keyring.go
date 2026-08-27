package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// MasterKeyLen is the required size of every key in the ring.
const MasterKeyLen = 32

// ErrUnknownKeyID means a stored record references a master key that is no
// longer in the ring. This is what a botched key rotation looks like, and it is
// worth alerting on: every record in that state is permanently unreadable.
var ErrUnknownKeyID = errors.New("crypto: unknown master key id")

// Keyring holds the master keys. The first entry is active for writing; the
// rest exist so that records written before a rotation stay readable.
//
// Wire format: "v2:<base64-32B>,v1:<base64-32B>", newest first.
type Keyring struct {
	activeID string
	keys     map[string][]byte
}

// ParseKeyring parses the keyring wire format.
func ParseKeyring(s string) (*Keyring, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("crypto: empty master keyring")
	}
	kr := &Keyring{keys: make(map[string][]byte)}
	for i, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, encoded, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("crypto: keyring entry %d: want <id>:<base64>, got %q", i, elide(entry))
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("crypto: keyring entry %d has an empty id", i)
		}
		raw, err := decodeKey(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("crypto: keyring entry %q: %w", id, err)
		}
		if _, dup := kr.keys[id]; dup {
			return nil, fmt.Errorf("crypto: keyring has duplicate id %q", id)
		}
		kr.keys[id] = raw
		if kr.activeID == "" {
			kr.activeID = id
		}
	}
	if kr.activeID == "" {
		return nil, errors.New("crypto: master keyring has no usable entries")
	}
	return kr, nil
}

// ActiveID returns the id of the key new records are written with.
func (kr *Keyring) ActiveID() string { return kr.activeID }

// Active returns the key new records are written with.
func (kr *Keyring) Active() []byte { return kr.keys[kr.activeID] }

// Lookup returns the key for a given id, for reading older records.
func (kr *Keyring) Lookup(id string) ([]byte, error) {
	k, ok := kr.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, id)
	}
	return k, nil
}

// Len reports how many keys are in the ring.
func (kr *Keyring) Len() int { return len(kr.keys) }

// IDs returns every key id in the ring. Ids are not secret.
func (kr *Keyring) IDs() []string {
	out := make([]string, 0, len(kr.keys))
	for id := range kr.keys {
		out = append(out, id)
	}
	return out
}

func (*Keyring) String() string               { return redacted }
func (*Keyring) GoString() string             { return redacted }
func (*Keyring) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (*Keyring) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// GenerateKeyringEntry mints a new entry suitable for the wire format.
func GenerateKeyringEntry(id string) (string, error) {
	var buf [MasterKeyLen]byte
	if err := randRead(buf[:]); err != nil {
		return "", err
	}
	return id + ":" + base64.StdEncoding.EncodeToString(buf[:]), nil
}

func decodeKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			if len(raw) != MasterKeyLen {
				return nil, fmt.Errorf("want %d bytes, got %d", MasterKeyLen, len(raw))
			}
			return raw, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// elide keeps malformed-input errors from echoing what might be key material.
func elide(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "..."
}
