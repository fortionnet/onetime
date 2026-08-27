package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SaltLen is the size of the per-record KDF salt.
const SaltLen = 16

const infoKEK = "onetime/v1/kek"

// KDFParams are the Argon2id cost parameters. Defaults follow the OWASP
// minimum: 19 MiB, two passes, one lane.
type KDFParams struct {
	MemKiB uint32
	Time   uint32
	Par    uint8
}

// String renders the parameters for storage alongside the record, so that
// records written under older settings stay readable after a config change.
func (p KDFParams) String() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.MemKiB, p.Time, p.Par)
}

// ParseKDFParams reads back the String form.
func ParseKDFParams(s string) (KDFParams, error) {
	var p KDFParams
	if _, err := fmt.Sscanf(s, "m=%d,t=%d,p=%d", &p.MemKiB, &p.Time, &p.Par); err != nil {
		return KDFParams{}, fmt.Errorf("crypto: parse kdf params %q: %w", s, err)
	}
	if p.MemKiB == 0 || p.Time == 0 || p.Par == 0 {
		return KDFParams{}, fmt.Errorf("crypto: kdf params %q has a zero component", s)
	}
	return p, nil
}

// Deriver turns a fragment key (plus an optional passphrase) into the key
// encryption key that wraps a record's data key. It owns the master keyring so
// that no other package needs to touch raw key material.
type Deriver struct {
	ring   *Keyring
	params KDFParams
	// sem bounds concurrent Argon2id invocations. Each one pins MemKiB of RAM,
	// so without this a burst of passphrase attempts is a memory-exhaustion
	// vector against our own pod.
	sem chan struct{}
}

// NewDeriver builds a Deriver. concurrency caps simultaneous Argon2id runs;
// peak KDF memory is concurrency * params.MemKiB.
func NewDeriver(ring *Keyring, params KDFParams, concurrency int) *Deriver {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Deriver{ring: ring, params: params, sem: make(chan struct{}, concurrency)}
}

// Ring exposes the keyring for startup checks and rotation diagnostics.
func (d *Deriver) Ring() *Keyring { return d.ring }

// Params returns the Argon2id parameters used for new records.
func (d *Deriver) Params() KDFParams { return d.params }

// NewSalt returns a fresh per-record salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypto: generate salt: %w", err)
	}
	return salt, nil
}

// KEK derives the key encryption key for a record.
//
// Without a passphrase the input keying material is the fragment key and the
// master key. There is deliberately no slow KDF in that path: the fragment key
// is 256 bits of CSPRNG output, so stretching it buys nothing and would only
// hand an attacker a cheap way to burn our CPU on the reveal endpoint.
//
// With a passphrase the user-chosen part is low entropy, so it goes through
// Argon2id first and is folded into the same HKDF.
func (d *Deriver) KEK(keyID string, k Key, pass Passphrase, salt []byte, params KDFParams) ([32]byte, error) {
	var out [32]byte
	master, err := d.ring.Lookup(keyID)
	if err != nil {
		return out, err
	}
	if len(salt) != SaltLen {
		return out, fmt.Errorf("crypto: salt must be %d bytes, got %d", SaltLen, len(salt))
	}

	ikm := make([]byte, 0, KeyLen+32+MasterKeyLen)
	ikm = append(ikm, k[:]...)
	if !pass.Empty() {
		stretched, err := d.argon2(pass, salt, master, params)
		if err != nil {
			return out, err
		}
		ikm = append(ikm, stretched...)
		zero(stretched)
	}
	ikm = append(ikm, master...)
	defer zero(ikm)

	kek, err := hkdf.Key(sha256.New, ikm, salt, infoKEK, 32)
	if err != nil {
		return out, fmt.Errorf("crypto: derive kek: %w", err)
	}
	copy(out[:], kek)
	zero(kek)
	return out, nil
}

func (d *Deriver) argon2(pass Passphrase, salt, master []byte, p KDFParams) ([]byte, error) {
	if p.MemKiB == 0 || p.Time == 0 || p.Par == 0 {
		return nil, fmt.Errorf("crypto: invalid argon2 params %s", p)
	}
	// Binding the salt to the master key means an attacker who steals the
	// database but not the key cannot even mount an offline dictionary attack
	// against the passphrase.
	bound := make([]byte, 0, len(salt)+len(master))
	bound = append(bound, salt...)
	bound = append(bound, master...)
	defer zero(bound)

	d.sem <- struct{}{}
	defer func() { <-d.sem }()
	return argon2.IDKey(pass, bound, p.Time, p.MemKiB, p.Par, 32), nil
}

func randRead(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("crypto: read random: %w", err)
	}
	return nil
}

// zero best-effort scrubs a buffer. Go gives no guarantee the compiler keeps
// this, and it does nothing about copies the GC already moved, but it shortens
// the window in which key material sits in reusable memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
