package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir+"/blobs", dir+"/tmp")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func write(t *testing.T, s *Store, meta Sidecar, body []byte) string {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if _, err := s.Create(id, meta, func(w io.Writer) error {
		_, err := w.Write(body)
		return err
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return id
}

func TestWriteReadDelete(t *testing.T) {
	s := newTestStore(t)
	payload := bytes.Repeat([]byte("x"), 5000)
	id := write(t, s, Sidecar{SecretID: "sid1", Expires: time.Now().Add(time.Hour).Unix()}, payload)

	f, err := s.Open(id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = f.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("stored bytes differ from what was written")
	}

	meta, err := s.ReadSidecar(id)
	if err != nil {
		t.Fatalf("ReadSidecar: %v", err)
	}
	if meta.SecretID != "sid1" || meta.EncSize != int64(len(payload)) || meta.ID != id {
		t.Fatalf("unexpected sidecar: %+v", meta)
	}

	freed, err := s.Delete(id)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if freed != int64(len(payload)) {
		t.Fatalf("Delete reported %d bytes freed, want %d", freed, len(payload))
	}
	if _, err := s.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open after delete = %v, want ErrNotFound", err)
	}
	// The sidecar must go too, or the collector will keep finding a ghost.
	if _, err := s.ReadSidecar(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadSidecar after delete = %v, want ErrNotFound", err)
	}
}

// TestFailedWriteLeavesNothingBehind covers the reason writes go through a
// staging file and a rename: an upload that dies partway must not leave a
// truncated blob that Redis believes is complete.
func TestFailedWriteLeavesNothingBehind(t *testing.T) {
	s := newTestStore(t)
	id, _ := NewID()
	boom := errors.New("connection reset")

	_, err := s.Create(id, Sidecar{SecretID: "sid"}, func(w io.Writer) error {
		if _, err := w.Write([]byte("partial")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Create error = %v, want the writer's error", err)
	}
	if _, err := s.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("a failed write left a blob behind")
	}
	entries, err := os.ReadDir(s.tmp)
	if err != nil {
		t.Fatalf("read staging dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed write left %d files in the staging directory", len(entries))
	}
}

func TestPurgeTmpClearsAbandonedUploads(t *testing.T) {
	s := newTestStore(t)
	for range 3 {
		f, err := os.CreateTemp(s.tmp, "up-*.part")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		_ = f.Close()
	}
	n, err := s.PurgeTmp()
	if err != nil {
		t.Fatalf("PurgeTmp: %v", err)
	}
	if n != 3 {
		t.Fatalf("PurgeTmp removed %d files, want 3", n)
	}
}

func TestIDValidationRejectsPathTraversal(t *testing.T) {
	s := newTestStore(t)
	for _, id := range []string{"", "short", "../../etc/passwd", "zz" + string(make([]byte, 62))} {
		if _, err := s.Open(id); err == nil {
			t.Errorf("Open(%q) succeeded, want a rejection", id)
		}
		if _, err := s.Delete(id); err == nil {
			t.Errorf("Delete(%q) succeeded, want a rejection", id)
		}
	}
}

func TestUsageCountsEverything(t *testing.T) {
	s := newTestStore(t)
	write(t, s, Sidecar{SecretID: "a"}, bytes.Repeat([]byte("a"), 100))
	write(t, s, Sidecar{SecretID: "b"}, bytes.Repeat([]byte("b"), 200))

	total, count, err := s.Usage()
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if total != 300 || count != 2 {
		t.Fatalf("Usage = %d bytes in %d files, want 300 in 2", total, count)
	}
}

// fakeIndex stands in for Redis so the collector's decisions can be driven
// precisely.
type fakeIndex struct {
	mu         sync.Mutex
	due        []string
	referenced map[string]string // blobID -> secretID that still owns it
	usage      int64
	scheduled  map[string]time.Time
	forgotten  []string
}

func newFakeIndex() *fakeIndex {
	return &fakeIndex{referenced: map[string]string{}, scheduled: map[string]time.Time{}}
}

func (f *fakeIndex) DueBlobs(context.Context, time.Time, int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.due...), nil
}

func (f *fakeIndex) ForgetBlob(_ context.Context, ids ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgotten = append(f.forgotten, ids...)
	return nil
}

func (f *fakeIndex) ScheduleBlob(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduled[id] = at
	return nil
}

func (f *fakeIndex) BlobReferenced(_ context.Context, sid, blobID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.referenced[blobID] == sid && sid != "", nil
}

func (f *fakeIndex) SetDiskUsage(_ context.Context, total int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage = total
	return nil
}

func (f *fakeIndex) AddDiskUsage(_ context.Context, delta int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage += delta
	return nil
}

func newTestCollector(t *testing.T) (*Store, *fakeIndex, *Collector) {
	t.Helper()
	s := newTestStore(t)
	idx := newFakeIndex()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return s, idx, NewCollector(s, idx, log, time.Hour)
}

func TestSweepDeletesUnreferencedButKeepsLiveOnes(t *testing.T) {
	s, idx, c := newTestCollector(t)
	ctx := context.Background()

	dead := write(t, s, Sidecar{SecretID: "dead"}, []byte("gone"))
	live := write(t, s, Sidecar{SecretID: "live"}, []byte("still here"))
	idx.referenced[live] = "live"
	idx.due = []string{dead, live}

	stats, err := c.Sweep(ctx, time.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Deleted != 1 || stats.Kept != 1 {
		t.Fatalf("Sweep deleted %d and kept %d, want 1 and 1", stats.Deleted, stats.Kept)
	}
	if _, err := s.Open(dead); !errors.Is(err, ErrNotFound) {
		t.Error("an unreferenced blob survived the sweep")
	}
	if _, err := s.Open(live); err != nil {
		t.Errorf("a referenced blob was deleted: %v", err)
	}
}

// TestReconcileReclaimsOrphansAfterRedisLoss is the scenario the reconcile pass
// exists for: with Redis emptied, nothing on the volume is referenced any more
// and every file is dead weight nobody will ever ask for.
func TestReconcileReclaimsOrphansAfterRedisLoss(t *testing.T) {
	s, idx, c := newTestCollector(t)
	ctx := context.Background()
	now := time.Now()

	stale := write(t, s, Sidecar{SecretID: "gone", Expires: now.Add(time.Hour).Unix()}, []byte("orphan"))
	// Backdate it past the grace period.
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(s.Path(stale), old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	stats, err := c.Reconcile(ctx, now)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.Orphans != 1 || stats.Deleted != 1 {
		t.Fatalf("Reconcile found %d orphans and deleted %d, want 1 and 1", stats.Orphans, stats.Deleted)
	}
	if idx.usage != 0 {
		t.Fatalf("disk usage after reclaiming everything = %d, want 0", idx.usage)
	}
}

// TestReconcileSparesRecentUploads is the other half: a blob being written
// right now has no reference yet, and deleting it would destroy a secret as it
// was being created.
func TestReconcileSparesRecentUploads(t *testing.T) {
	s, _, c := newTestCollector(t)
	fresh := write(t, s, Sidecar{SecretID: "inflight", Expires: time.Now().Add(time.Hour).Unix()}, []byte("new"))

	if _, err := c.Reconcile(context.Background(), time.Now()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := s.Open(fresh); err != nil {
		t.Fatalf("reconcile deleted an upload inside the grace period: %v", err)
	}
}

func TestReconcileDeletesExpiredRegardlessOfAge(t *testing.T) {
	s, _, c := newTestCollector(t)
	now := time.Now()
	expired := write(t, s, Sidecar{SecretID: "old", Expires: now.Add(-time.Minute).Unix()}, []byte("stale"))

	if _, err := c.Reconcile(context.Background(), now); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := s.Open(expired); !errors.Is(err, ErrNotFound) {
		t.Fatal("an expired blob survived reconcile")
	}
}

func TestReconcileDeletesBlobWithoutSidecar(t *testing.T) {
	s, _, c := newTestCollector(t)
	now := time.Now()
	id := write(t, s, Sidecar{SecretID: "x", Expires: now.Add(time.Hour).Unix()}, []byte("body"))

	// Simulate a crash between the blob rename and the sidecar rename.
	if err := os.Remove(s.metaPath(id)); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}
	old := now.Add(-2 * time.Hour)
	_ = os.Chtimes(s.Path(id), old, old)

	if _, err := c.Reconcile(context.Background(), now); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := s.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("a blob with no sidecar survived past the grace period")
	}
}

func TestReconcileReschedulesLiveBlobs(t *testing.T) {
	s, idx, c := newTestCollector(t)
	now := time.Now()
	expires := now.Add(time.Hour)
	id := write(t, s, Sidecar{SecretID: "live", Expires: expires.Unix()}, []byte("body"))
	idx.referenced[id] = "live"

	if _, err := c.Reconcile(context.Background(), now); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Losing Redis loses the collection schedule too; reconcile has to put it
	// back, or these blobs would sit on the volume until it filled up.
	if got, ok := idx.scheduled[id]; !ok || got.Unix() != expires.Unix() {
		t.Fatalf("live blob was not rescheduled: %v", idx.scheduled)
	}
}

func TestSpaceReportsSomethingSensible(t *testing.T) {
	s := newTestStore(t)
	space, err := s.Space()
	if err != nil {
		t.Fatalf("Space: %v", err)
	}
	if space.TotalBytes <= 0 || space.FreeBytes < 0 {
		t.Fatalf("implausible capacity: %+v", space)
	}
	if r := space.UsedRatio(); r < 0 || r > 1 {
		t.Fatalf("UsedRatio = %v, want a fraction between 0 and 1", r)
	}
}

func TestShardingSpreadsFilesAcrossDirectories(t *testing.T) {
	s := newTestStore(t)
	id := write(t, s, Sidecar{SecretID: "x"}, []byte("body"))
	// The path must nest, or a busy volume ends up with one directory holding
	// tens of thousands of entries.
	rel, err := filepath.Rel(s.dir, s.Path(id))
	if err != nil {
		t.Fatalf("Rel: %v", err)
	}
	if depth := len(filepath.SplitList(rel)); depth != 1 {
		t.Fatalf("unexpected path shape %q", rel)
	}
	parts := filepath.ToSlash(rel)
	if got := len(bytes.Split([]byte(parts), []byte("/"))); got != 3 {
		t.Fatalf("blob path %q has %d components, want 3 (two shard levels plus the file)", parts, got)
	}
}
