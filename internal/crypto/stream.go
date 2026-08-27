package crypto

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The payload format is the STREAM construction (Hoang-Reyhanitabar-Rogaway),
// the same shape used by age and Tink. A single AES-GCM message cannot cover
// 50 MB and could not be streamed anyway, so the plaintext is split into fixed
// chunks, each sealed under a nonce built from a random prefix, the chunk
// counter and a final-chunk flag.
//
// The counter makes chunk reordering and replay detectable; the final flag
// makes truncation detectable. Both matter: without the flag an attacker could
// silently cut a file short, and the recipient would have no way to tell.
const (
	chunkSize = 64 << 10
	tagLen    = 16
	magic     = "OTS1"
	prefixLen = 7
	headerLen = len(magic) + prefixLen
	nonceLen  = prefixLen + 4 + 1
)

var (
	// ErrCorruptStream means the payload failed authentication: truncated,
	// reordered, tampered with, or written by a writer that was never closed.
	ErrCorruptStream = errors.New("crypto: payload failed authentication")
	errTrailingData  = errors.New("crypto: trailing data after final chunk")
)

// EncryptedSize reports how many bytes on disk a plaintext of n bytes occupies.
func EncryptedSize(n int64) int64 {
	chunks := (n + chunkSize - 1) / chunkSize
	if chunks == 0 {
		chunks = 1 // the final chunk is always emitted, even for empty input
	}
	return int64(headerLen) + n + chunks*tagLen
}

type streamWriter struct {
	dst     io.Writer
	gcm     cipher.AEAD
	aad     []byte
	prefix  [prefixLen]byte
	buf     []byte
	n       int
	counter uint32
	started bool
	closed  bool
}

// NewStreamWriter returns a writer that encrypts everything written to it.
//
// Close must be called: it emits the final chunk, and without it the resulting
// payload is deliberately unreadable rather than silently truncated.
func NewStreamWriter(dek DEK, dst io.Writer, aad []byte) (io.WriteCloser, error) {
	gcm, err := newGCM(dek[:])
	if err != nil {
		return nil, err
	}
	w := &streamWriter{dst: dst, gcm: gcm, aad: aad, buf: make([]byte, chunkSize)}
	if err := randRead(w.prefix[:]); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("crypto: write after close")
	}
	total := 0
	for len(p) > 0 {
		// A full buffer is only flushed once we know more data follows, so the
		// last chunk is always the one Close seals with the final flag.
		if w.n == chunkSize {
			if err := w.flush(false); err != nil {
				return total, err
			}
		}
		c := copy(w.buf[w.n:], p)
		w.n += c
		p = p[c:]
		total += c
	}
	return total, nil
}

func (w *streamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flush(true)
}

func (w *streamWriter) flush(final bool) error {
	if !w.started {
		if _, err := w.dst.Write(append([]byte(magic), w.prefix[:]...)); err != nil {
			return fmt.Errorf("crypto: write stream header: %w", err)
		}
		w.started = true
	}
	if !final && w.counter == ^uint32(0) {
		return errors.New("crypto: stream too long")
	}
	nonce := makeNonce(w.prefix, w.counter, final)
	sealed := w.gcm.Seal(nil, nonce[:], w.buf[:w.n], w.aad)
	if _, err := w.dst.Write(sealed); err != nil {
		return fmt.Errorf("crypto: write chunk %d: %w", w.counter, err)
	}
	w.counter++
	w.n = 0
	return nil
}

type streamReader struct {
	src     *bufio.Reader
	gcm     cipher.AEAD
	aad     []byte
	prefix  [prefixLen]byte
	pending []byte
	counter uint32
	started bool
	done    bool
	err     error
}

// NewStreamReader returns a reader that decrypts a payload written by
// NewStreamWriter, verifying every chunk before handing any of it back.
func NewStreamReader(dek DEK, src io.Reader, aad []byte) (io.Reader, error) {
	gcm, err := newGCM(dek[:])
	if err != nil {
		return nil, err
	}
	// The buffer must hold a full chunk plus its tag plus one lookahead byte:
	// that byte is how we tell a full middle chunk from a full final chunk.
	return &streamReader{
		src: bufio.NewReaderSize(src, chunkSize+tagLen+1),
		gcm: gcm,
		aad: aad,
	}, nil
}

func (r *streamReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			r.err = io.EOF
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *streamReader) next() error {
	if !r.started {
		head := make([]byte, headerLen)
		if _, err := io.ReadFull(r.src, head); err != nil {
			return ErrCorruptStream
		}
		if string(head[:len(magic)]) != magic {
			return ErrCorruptStream
		}
		copy(r.prefix[:], head[len(magic):])
		r.started = true
	}

	const want = chunkSize + tagLen + 1
	peeked, err := r.src.Peek(want)
	switch {
	case err == nil && len(peeked) == want:
		// A whole chunk plus at least one more byte: this is a middle chunk.
		return r.open(chunkSize+tagLen, false)
	case errors.Is(err, io.EOF):
		if len(peeked) < tagLen {
			return ErrCorruptStream
		}
		if openErr := r.open(len(peeked), true); openErr != nil {
			return openErr
		}
		r.done = true
		if _, peekErr := r.src.Peek(1); peekErr == nil {
			return errTrailingData
		}
		return nil
	default:
		return fmt.Errorf("crypto: read chunk %d: %w", r.counter, err)
	}
}

func (r *streamReader) open(n int, final bool) error {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.src, buf); err != nil {
		return ErrCorruptStream
	}
	nonce := makeNonce(r.prefix, r.counter, final)
	plain, err := r.gcm.Open(buf[:0], nonce[:], buf, r.aad)
	if err != nil {
		return ErrCorruptStream
	}
	r.counter++
	r.pending = plain
	return nil
}

func makeNonce(prefix [prefixLen]byte, counter uint32, final bool) [nonceLen]byte {
	var nonce [nonceLen]byte
	copy(nonce[:prefixLen], prefix[:])
	binary.BigEndian.PutUint32(nonce[prefixLen:prefixLen+4], counter)
	if final {
		nonce[nonceLen-1] = 1
	}
	return nonce
}

// SealBytes encrypts a whole value in memory using the same stream format, so
// short text secrets stored inline in Redis and large files on disk share one
// code path and one set of tests.
func SealBytes(dek DEK, plaintext, aad []byte) ([]byte, error) {
	var out sliceWriter
	w, err := NewStreamWriter(dek, &out, aad)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.b, nil
}

// OpenBytes reverses SealBytes.
func OpenBytes(dek DEK, sealed, aad []byte) (Plaintext, error) {
	r, err := NewStreamReader(dek, byteReader(sealed), aad)
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Plaintext(out), nil
}

type sliceWriter struct{ b []byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func byteReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
