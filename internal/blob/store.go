// Package blob stores encrypted payloads on the persistent volume.
//
// It knows nothing about encryption: callers hand it a function that writes
// already-sealed bytes. What it does own is durability and the ordering rule
// that keeps the volume consistent with Redis.
package blob

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto/rand"
)

const (
	blobExt    = ".bin"
	metaExt    = ".json"
	idBytes    = 32
	dirPerm    = 0o700
	filePerm   = 0o600
	tmpPattern = "up-*.part"
)

// ErrNotFound means no blob exists for the given id.
var ErrNotFound = errors.New("blob: not found")

// Sidecar is the small JSON file written next to every blob. It duplicates
// just enough of the Redis record for the garbage collector to work with
// nothing but the volume, which is what makes recovery possible after Redis is
// flushed or its append-only file is lost.
type Sidecar struct {
	Version  int    `json:"v"`
	ID       string `json:"blob"`
	SecretID string `json:"sid"`
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires"`
	EncSize  int64  `json:"enc_size"`
}

// Store is a sharded directory of encrypted blobs.
type Store struct {
	dir string
	tmp string
}

// New prepares the blob and staging directories.
func New(dir, tmp string) (*Store, error) {
	for _, d := range []string{dir, tmp} {
		if err := os.MkdirAll(d, dirPerm); err != nil {
			return nil, fmt.Errorf("blob: create %s: %w", d, err)
		}
	}
	return &Store{dir: dir, tmp: tmp}, nil
}

// NewID mints a blob id. It is random and independent of the secret's key and
// id, so a directory listing of the volume reveals nothing about what is stored
// or who it belongs to.
func NewID() (string, error) {
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("blob: generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Path returns the on-disk location of a blob.
func (s *Store) Path(id string) string {
	return filepath.Join(s.dir, id[0:2], id[2:4], id+blobExt)
}

func (s *Store) metaPath(id string) string {
	return filepath.Join(s.dir, id[0:2], id[2:4], id+metaExt)
}

// Create writes a blob durably, then its sidecar.
//
// The caller writes into the supplied writer; nothing is buffered whole, so a
// 50 MB upload costs a 64 KiB buffer rather than 50 MB of heap.
//
// Everything lands under a temporary name and is renamed into place only once
// it is complete and flushed. A crash mid-upload therefore leaves a stray file
// in the staging directory, which is cleared on startup, never a half-written
// blob that Redis believes is whole.
func (s *Store) Create(id string, meta Sidecar, write func(w io.Writer) error) (int64, error) {
	if err := validID(id); err != nil {
		return 0, err
	}
	dir := filepath.Dir(s.Path(id))
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return 0, fmt.Errorf("blob: create shard %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(s.tmp, tmpPattern)
	if err != nil {
		return 0, fmt.Errorf("blob: create staging file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(filePerm); err != nil {
		return 0, fmt.Errorf("blob: chmod staging file: %w", err)
	}
	counter := &countingWriter{w: tmp}
	if err := write(counter); err != nil {
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("blob: sync staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("blob: close staging file: %w", err)
	}
	if err := os.Rename(tmpName, s.Path(id)); err != nil {
		return 0, fmt.Errorf("blob: commit blob: %w", err)
	}
	committed = true

	meta.Version = 1
	meta.ID = id
	meta.EncSize = counter.n
	if err := s.writeSidecar(id, meta); err != nil {
		_ = os.Remove(s.Path(id))
		return 0, err
	}
	syncDir(dir)
	return counter.n, nil
}

func (s *Store) writeSidecar(id string, meta Sidecar) error {
	body, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("blob: marshal sidecar: %w", err)
	}
	tmp, err := os.CreateTemp(s.tmp, tmpPattern)
	if err != nil {
		return fmt.Errorf("blob: create staging sidecar: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blob: chmod staging sidecar: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blob: write staging sidecar: %w", err)
	}
	if err := errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("blob: flush staging sidecar: %w", err)
	}
	if err := os.Rename(tmpName, s.metaPath(id)); err != nil {
		return fmt.Errorf("blob: commit sidecar: %w", err)
	}
	return nil
}

// Open returns a handle to a blob for streaming.
func (s *Store) Open(id string) (*os.File, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	f, err := os.Open(s.Path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("blob: open: %w", err)
	}
	return f, nil
}

// Delete removes a blob and its sidecar, reporting how many bytes were freed.
func (s *Store) Delete(id string) (int64, error) {
	if err := validID(id); err != nil {
		return 0, err
	}
	var freed int64
	if fi, err := os.Stat(s.Path(id)); err == nil {
		freed = fi.Size()
	}
	err := os.Remove(s.Path(id))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("blob: delete: %w", err)
	}
	if err := os.Remove(s.metaPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return freed, fmt.Errorf("blob: delete sidecar: %w", err)
	}
	return freed, nil
}

// ReadSidecar returns the metadata written alongside a blob.
func (s *Store) ReadSidecar(id string) (Sidecar, error) {
	var meta Sidecar
	body, err := os.ReadFile(s.metaPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return meta, ErrNotFound
	}
	if err != nil {
		return meta, fmt.Errorf("blob: read sidecar: %w", err)
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return meta, fmt.Errorf("blob: parse sidecar for %s: %w", id, err)
	}
	return meta, nil
}

// PurgeTmp clears the staging directory. Anything left there is the debris of
// an upload that died, so nothing in it should survive a restart.
func (s *Store) PurgeTmp() (int, error) {
	entries, err := os.ReadDir(s.tmp)
	if err != nil {
		return 0, fmt.Errorf("blob: read staging dir: %w", err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.tmp, e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// Entry is one blob found on the volume.
type Entry struct {
	ID      string
	Size    int64
	ModTime time.Time
	Sidecar Sidecar
	HasMeta bool
}

// Walk visits every blob on the volume.
func (s *Store) Walk(fn func(Entry) error) error {
	return filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), blobExt) {
			return nil
		}
		id := strings.TrimSuffix(d.Name(), blobExt)
		if validID(id) != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil // vanished under us; the next pass will catch it
		}
		entry := Entry{ID: id, Size: info.Size(), ModTime: info.ModTime()}
		if meta, err := s.ReadSidecar(id); err == nil {
			entry.Sidecar, entry.HasMeta = meta, true
		}
		return fn(entry)
	})
}

// Usage sums the bytes currently stored.
func (s *Store) Usage() (int64, int, error) {
	var total int64
	var count int
	err := s.Walk(func(e Entry) error {
		total += e.Size
		count++
		return nil
	})
	return total, count, err
}

func validID(id string) error {
	if len(id) != idBytes*2 {
		return fmt.Errorf("blob: id must be %d hex characters, got %d", idBytes*2, len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("blob: id is not hex: %w", err)
	}
	return nil
}

// syncDir flushes a directory entry so a rename survives a power loss. Failure
// is not fatal: some filesystems refuse to open a directory for sync, and the
// worst case is a blob the collector later treats as an orphan.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
