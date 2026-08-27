package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log/slog"
)

// DEKLen is the size of a data encryption key.
const DEKLen = 32

// WrappedDEKLen is nonce(12) + ciphertext(32) + tag(16).
const WrappedDEKLen = 12 + DEKLen + 16

// DEK is a per-record data encryption key. It is generated at random, wrapped
// under the KEK for storage, and never written down in the clear.
type DEK [DEKLen]byte

// NewDEK returns a fresh random data key.
func NewDEK() (DEK, error) {
	var d DEK
	if err := randRead(d[:]); err != nil {
		return DEK{}, err
	}
	return d, nil
}

func (DEK) String() string               { return redacted }
func (DEK) GoString() string             { return redacted }
func (DEK) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (DEK) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// WrapDEK seals the data key under the key encryption key.
//
// Wrapping the data key rather than encrypting the payload directly with the
// KEK buys two things. Verifying a passphrase becomes an unwrap of 32 bytes,
// so it costs the same whether the payload is a password or a 50 MB file. And
// rotating the master key later only needs the 60-byte wrapper rewritten, not
// the payload.
func WrapDEK(kek [32]byte, dek DEK, aad []byte) ([]byte, error) {
	gcm, err := newGCM(kek[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if err := randRead(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek[:], aad), nil
}

// UnwrapDEK opens a wrapped data key.
//
// A failure here is how a wrong passphrase is detected: no verifier is stored
// anywhere, so there is no offline-crackable artefact in the database. The cost
// is that a wrong passphrase and a corrupted record are indistinguishable; we
// report the former and watch the decrypt-failure metric for the latter.
func UnwrapDEK(kek [32]byte, wrapped, aad []byte) (DEK, error) {
	var dek DEK
	gcm, err := newGCM(kek[:])
	if err != nil {
		return dek, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns+DEKLen {
		return dek, ErrBadPassphrase
	}
	plain, err := gcm.Open(nil, wrapped[:ns], wrapped[ns:], aad)
	if err != nil {
		return dek, ErrBadPassphrase
	}
	if len(plain) != DEKLen {
		zero(plain)
		return dek, ErrBadPassphrase
	}
	copy(dek[:], plain)
	zero(plain)
	return dek, nil
}

// SealSmall encrypts a short value (a filename, a MIME type) under the data
// key. Use Stream for anything that should not be held in memory whole.
func SealSmall(dek DEK, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if err := randRead(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenSmall reverses SealSmall.
func OpenSmall(dek DEK, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek[:])
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, ErrBadPassphrase
	}
	plain, err := gcm.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return plain, nil
}

// AAD binds a ciphertext to the record it belongs to, so a wrapper or payload
// lifted from one record cannot be replayed into another.
func AAD(purpose, id, keyID string) []byte {
	return []byte("onetime/v1|" + purpose + "|" + id + "|" + keyID)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return gcm, nil
}
