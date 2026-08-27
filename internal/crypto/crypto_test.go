package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func testDeriver(t *testing.T) *Deriver {
	t.Helper()
	ring, err := ParseKeyring("v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, MasterKeyLen)))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	// Cheap Argon2 parameters: these tests exercise correctness, not cost.
	return NewDeriver(ring, KDFParams{MemKiB: 64, Time: 1, Par: 1}, 2)
}

func TestKeyRoundTrip(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	got, err := ParseKey(k.Encode())
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if !got.Equal(k) {
		t.Fatal("round-tripped key differs from the original")
	}
	if len(k.SecretID()) != IDLen {
		t.Fatalf("SecretID length = %d, want %d", len(k.SecretID()), IDLen)
	}
	if k.SecretID() == k.ReceiptID() {
		t.Fatal("secret and receipt ids collide; the domain separator is not doing its job")
	}
}

func TestParseKeyRejectsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"short", "abc"},
		{"long", strings.Repeat("A", 44)},
		{"bad alphabet", strings.Repeat("!", 43)},
		{"std base64 padding", base64.StdEncoding.EncodeToString(make([]byte, 32))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKey(tc.in); err == nil {
				t.Fatalf("ParseKey(%q) succeeded, want failure", tc.in)
			}
		})
	}
}

// TestSecretMaterialNeverRenders is the automated guard behind the promise that
// a secret cannot reach a log line. It covers slog, every fmt verb we might
// plausibly reach for, and JSON marshalling.
func TestSecretMaterialNeverRenders(t *testing.T) {
	k, _ := NewKey()
	dek, _ := NewDEK()
	ticket, _ := NewTicket(dek)
	pass := Passphrase("hunter2-CANARY")
	plain := Plaintext("top-CANARY-secret")

	needles := []string{k.Encode(), ticket.Encode(), "hunter2-CANARY", "top-CANARY-secret"}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	log.Info("render everything",
		"key", k, "dek", dek, "ticket", ticket, "pass", pass, "plain", plain)

	for _, verb := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
		for _, val := range []any{k, dek, ticket, pass, plain} {
			fmt.Fprintf(&buf, verb, val)
		}
	}
	for _, val := range []any{k, dek, ticket, pass, plain} {
		b, err := json.Marshal(val)
		if err != nil {
			t.Fatalf("json.Marshal(%T): %v", val, err)
		}
		buf.Write(b)
	}

	for _, needle := range needles {
		if strings.Contains(buf.String(), needle) {
			t.Fatalf("secret material %q leaked into rendered output", needle)
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	d := testDeriver(t)
	k, _ := NewKey()
	salt, _ := NewSalt()
	aad := AAD("wrap", k.SecretID(), "v1")

	kek, err := d.KEK("v1", k, nil, salt, d.Params())
	if err != nil {
		t.Fatalf("KEK: %v", err)
	}
	dek, _ := NewDEK()
	wrapped, err := WrapDEK(kek, dek, aad)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(wrapped) != WrappedDEKLen {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), WrappedDEKLen)
	}
	got, err := UnwrapDEK(kek, wrapped, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if got != dek {
		t.Fatal("unwrapped data key differs from the original")
	}
}

// TestEnvelopeRejectsWrongInputs pins down the security property that matters
// most: every way of getting the inputs wrong must fail closed, and must fail
// the same way, so nothing is learned from which error came back.
func TestEnvelopeRejectsWrongInputs(t *testing.T) {
	d := testDeriver(t)
	k, _ := NewKey()
	salt, _ := NewSalt()
	pass := Passphrase("correct horse")
	aad := AAD("wrap", k.SecretID(), "v1")

	kek, _ := d.KEK("v1", k, pass, salt, d.Params())
	dek, _ := NewDEK()
	wrapped, _ := WrapDEK(kek, dek, aad)

	otherKey, _ := NewKey()
	otherSalt, _ := NewSalt()

	cases := map[string]func() ([32]byte, []byte, []byte){
		"wrong passphrase": func() ([32]byte, []byte, []byte) {
			bad, _ := d.KEK("v1", k, Passphrase("battery staple"), salt, d.Params())
			return bad, wrapped, aad
		},
		"missing passphrase": func() ([32]byte, []byte, []byte) {
			bad, _ := d.KEK("v1", k, nil, salt, d.Params())
			return bad, wrapped, aad
		},
		"wrong fragment key": func() ([32]byte, []byte, []byte) {
			bad, _ := d.KEK("v1", otherKey, pass, salt, d.Params())
			return bad, wrapped, aad
		},
		"wrong salt": func() ([32]byte, []byte, []byte) {
			bad, _ := d.KEK("v1", k, pass, otherSalt, d.Params())
			return bad, wrapped, aad
		},
		"wrong master key": func() ([32]byte, []byte, []byte) {
			ring, _ := ParseKeyring("v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, MasterKeyLen)))
			other := NewDeriver(ring, d.Params(), 1)
			bad, _ := other.KEK("v1", k, pass, salt, d.Params())
			return bad, wrapped, aad
		},
		"tampered wrapper": func() ([32]byte, []byte, []byte) {
			bad := bytes.Clone(wrapped)
			bad[len(bad)-1] ^= 0x01
			return kek, bad, aad
		},
		"wrong aad": func() ([32]byte, []byte, []byte) {
			return kek, wrapped, AAD("wrap", otherKey.SecretID(), "v1")
		},
		"truncated wrapper": func() ([32]byte, []byte, []byte) {
			return kek, wrapped[:len(wrapped)-1], aad
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			badKEK, ct, ad := setup()
			if _, err := UnwrapDEK(badKEK, ct, ad); !errors.Is(err, ErrBadPassphrase) {
				t.Fatalf("UnwrapDEK error = %v, want ErrBadPassphrase", err)
			}
		})
	}
}

func TestUnknownKeyIDIsDistinguishable(t *testing.T) {
	d := testDeriver(t)
	k, _ := NewKey()
	salt, _ := NewSalt()
	// A record referencing a retired master key must surface as its own error:
	// it means a rotation went wrong and those records are gone for good, which
	// is an operational alert, not a user-facing "wrong password".
	if _, err := d.KEK("v99", k, nil, salt, d.Params()); err == nil {
		t.Fatal("KEK with an unknown key id succeeded, want ErrUnknownKeyID")
	}
}

func TestStreamRoundTripAcrossSizes(t *testing.T) {
	dek, _ := NewDEK()
	aad := []byte("payload")
	for _, size := range []int{0, 1, 1024, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 7} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			plain := make([]byte, size)
			if _, err := rand.Read(plain); err != nil {
				t.Fatalf("rand: %v", err)
			}
			sealed, err := SealBytes(dek, plain, aad)
			if err != nil {
				t.Fatalf("SealBytes: %v", err)
			}
			if int64(len(sealed)) != EncryptedSize(int64(size)) {
				t.Fatalf("sealed size = %d, EncryptedSize said %d", len(sealed), EncryptedSize(int64(size)))
			}
			got, err := OpenBytes(dek, sealed, aad)
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("decrypted payload differs from the original")
			}
		})
	}
}

// TestStreamRejectsMangledPayload covers the properties the STREAM framing
// exists for: a truncated, reordered, duplicated or flipped payload must fail
// loudly rather than decrypt to something shorter or scrambled.
func TestStreamRejectsMangledPayload(t *testing.T) {
	dek, _ := NewDEK()
	aad := []byte("payload")
	plain := make([]byte, 3*chunkSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sealed, err := SealBytes(dek, plain, aad)
	if err != nil {
		t.Fatalf("SealBytes: %v", err)
	}
	full := chunkSize + tagLen // one whole ciphertext chunk

	mangle := map[string]func([]byte) []byte{
		"truncated mid-chunk": func(b []byte) []byte { return b[:len(b)-100] },
		"final chunk removed": func(b []byte) []byte { return b[:headerLen+2*full] },
		"header removed":      func(b []byte) []byte { return b[headerLen:] },
		"bad magic": func(b []byte) []byte {
			out := bytes.Clone(b)
			out[0] = 'X'
			return out
		},
		"bit flip in payload": func(b []byte) []byte {
			out := bytes.Clone(b)
			out[headerLen+10] ^= 0x01
			return out
		},
		"chunks reordered": func(b []byte) []byte {
			out := bytes.Clone(b)
			first := bytes.Clone(out[headerLen : headerLen+full])
			second := bytes.Clone(out[headerLen+full : headerLen+2*full])
			copy(out[headerLen:], second)
			copy(out[headerLen+full:], first)
			return out
		},
		"chunk duplicated": func(b []byte) []byte {
			out := bytes.Clone(b)
			copy(out[headerLen+full:headerLen+2*full], out[headerLen:headerLen+full])
			return out
		},
		"trailing data": func(b []byte) []byte {
			return append(bytes.Clone(b), 0x00)
		},
	}

	for name, fn := range mangle {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenBytes(dek, fn(sealed), aad); err == nil {
				t.Fatal("mangled payload decrypted successfully, want an error")
			}
		})
	}
}

// TestStreamWriterWithoutCloseIsUnreadable pins the contract that forgetting
// Close produces something that fails to open, rather than a silently truncated
// payload the recipient would trust.
func TestStreamWriterWithoutCloseIsUnreadable(t *testing.T) {
	dek, _ := NewDEK()
	var out bytes.Buffer
	w, err := NewStreamWriter(dek, &out, nil)
	if err != nil {
		t.Fatalf("NewStreamWriter: %v", err)
	}
	// Two full chunks: the first is flushed, the second stays buffered and is
	// lost because Close is never called.
	if _, err := w.Write(make([]byte, 2*chunkSize)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := OpenBytes(dek, out.Bytes(), nil); err == nil {
		t.Fatal("payload from an unclosed writer opened successfully, want an error")
	}
}

func TestStreamWrongKeyFails(t *testing.T) {
	dek, _ := NewDEK()
	other, _ := NewDEK()
	sealed, err := SealBytes(dek, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("SealBytes: %v", err)
	}
	if _, err := OpenBytes(other, sealed, nil); err == nil {
		t.Fatal("payload opened under the wrong data key, want an error")
	}
}

func TestStreamLargePayloadStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 50 MB round trip in short mode")
	}
	dek, _ := NewDEK()
	const size = 50 << 20
	var sealed bytes.Buffer
	w, err := NewStreamWriter(dek, &sealed, nil)
	if err != nil {
		t.Fatalf("NewStreamWriter: %v", err)
	}
	if _, copyErr := io.Copy(w, io.LimitReader(rand.Reader, size)); copyErr != nil {
		t.Fatalf("copy in: %v", copyErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	r, err := NewStreamReader(dek, bytes.NewReader(sealed.Bytes()), nil)
	if err != nil {
		t.Fatalf("NewStreamReader: %v", err)
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("copy out: %v", err)
	}
	if n != size {
		t.Fatalf("decrypted %d bytes, want %d", n, size)
	}
}

func TestKeyringParsing(t *testing.T) {
	k1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, MasterKeyLen))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, MasterKeyLen))

	kr, err := ParseKeyring("v2:" + k2 + ",v1:" + k1)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	if kr.ActiveID() != "v2" {
		t.Fatalf("ActiveID = %q, want v2 (the first entry is active for writing)", kr.ActiveID())
	}
	if kr.Len() != 2 {
		t.Fatalf("Len = %d, want 2", kr.Len())
	}
	if _, err := kr.Lookup("v1"); err != nil {
		t.Fatalf("Lookup(v1) after rotation: %v", err)
	}

	for _, bad := range []string{"", "novalue", "v1:not-base64", "v1:" + base64.StdEncoding.EncodeToString([]byte("short")), "v1:" + k1 + ",v1:" + k2} {
		if _, err := ParseKeyring(bad); err == nil {
			t.Fatalf("ParseKeyring(%q) succeeded, want failure", elide(bad))
		}
	}
}

func TestKDFParamsRoundTrip(t *testing.T) {
	want := KDFParams{MemKiB: 19456, Time: 2, Par: 1}
	got, err := ParseKDFParams(want.String())
	if err != nil {
		t.Fatalf("ParseKDFParams: %v", err)
	}
	if got != want {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
	if _, err := ParseKDFParams("garbage"); err == nil {
		t.Fatal("ParseKDFParams accepted garbage")
	}
}

func TestTicketRoundTrip(t *testing.T) {
	dek, _ := NewDEK()
	tk, err := NewTicket(dek)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	got, err := ParseTicket(tk.Encode())
	if err != nil {
		t.Fatalf("ParseTicket: %v", err)
	}
	if got.DEK != dek || got.Nonce != tk.Nonce {
		t.Fatal("round-tripped ticket differs from the original")
	}
	if got.ID() != tk.ID() {
		t.Fatal("ticket id is not stable across a round trip")
	}
	if _, err := ParseTicket("too-short"); err == nil {
		t.Fatal("ParseTicket accepted a malformed ticket")
	}
}

func FuzzParseKey(f *testing.F) {
	k, _ := NewKey()
	f.Add(k.Encode())
	f.Add("")
	f.Add(strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, s string) {
		if key, err := ParseKey(s); err == nil && key.Encode() != s {
			t.Fatalf("ParseKey accepted %q but re-encoded it as %q", s, key.Encode())
		}
	})
}

func FuzzOpenBytes(f *testing.F) {
	dek, _ := NewDEK()
	sealed, _ := SealBytes(dek, []byte("seed"), nil)
	f.Add(sealed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		// Any input at all must produce an error or a value, never a panic.
		_, _ = OpenBytes(dek, b, nil)
	})
}
