package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewWithClient(client), mr
}

func seedSecret(t *testing.T, s *Redis, sid, mid string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sec := &Secret{
		State:      StateNew,
		Kind:       KindText,
		Alg:        AlgV1,
		KeyID:      "v1",
		Salt:       []byte("0123456789abcdef"),
		WrappedDEK: []byte("wrapped-key-material"),
		Payload:    []byte("ciphertext"),
		PlainSize:  10,
		ReceiptID:  mid,
		Created:    now,
		Expires:    now.Add(14 * 24 * time.Hour),
	}
	rec := &Receipt{
		State:         StateNew,
		Kind:          KindText,
		SecretID:      sid,
		PlainSize:     10,
		Created:       now,
		SecretExpires: sec.Expires,
		Expires:       sec.Expires.Add(7 * 24 * time.Hour),
	}
	if err := s.CreateSecret(context.Background(), sid, mid, sec, rec, 14*24*time.Hour, 21*24*time.Hour); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
}

func TestCreateAndLoadSecret(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	got, err := s.LoadSecret(ctx, "sid1")
	if err != nil {
		t.Fatalf("LoadSecret: %v", err)
	}
	if got.State != StateNew || got.Kind != KindText || got.KeyID != "v1" {
		t.Fatalf("unexpected record: %+v", got)
	}
	if string(got.Payload) != "ciphertext" || string(got.WrappedDEK) != "wrapped-key-material" {
		t.Fatal("payload or wrapped key did not survive the round trip")
	}
	if got.ReceiptID != "mid1" {
		t.Fatalf("ReceiptID = %q, want mid1", got.ReceiptID)
	}

	if _, err := s.LoadSecret(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("LoadSecret(missing) error = %v, want ErrNotFound", err)
	}
}

// TestClaimSecretConcurrent is the test the whole design hangs on: under
// simultaneous reveals exactly one caller may win.
func TestClaimSecretConcurrent(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	const racers = 100
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		wins  int
		lost  int
	)
	start.Add(1)
	done.Add(racers)
	for range racers {
		go func() {
			defer done.Done()
			start.Wait()
			claim, err := s.ClaimSecret(ctx, "sid1", "mid1", StateConsumed, time.Now(), time.Hour)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("ClaimSecret: %v", err)
				return
			}
			if claim.Won {
				wins++
				if string(claim.Payload) != "ciphertext" {
					t.Errorf("winning claim returned payload %q", claim.Payload)
				}
			} else {
				lost++
			}
		}()
	}
	start.Done()
	done.Wait()

	if wins != 1 {
		t.Fatalf("%d callers won the claim, want exactly 1", wins)
	}
	if lost != racers-1 {
		t.Fatalf("%d callers lost, want %d", lost, racers-1)
	}
}

// TestClaimSecretLeavesTombstone checks that consuming a secret really does
// destroy the material needed to read it, while keeping enough to tell the next
// visitor what happened.
func TestClaimSecretLeavesTombstone(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	if _, err := s.ClaimSecret(ctx, "sid1", "mid1", StateConsumed, time.Now(), time.Hour); err != nil {
		t.Fatalf("ClaimSecret: %v", err)
	}

	after, err := s.LoadSecret(ctx, "sid1")
	if err != nil {
		t.Fatalf("LoadSecret after claim: %v", err)
	}
	if after.State != StateConsumed {
		t.Fatalf("state = %q, want %q", after.State, StateConsumed)
	}
	for name, field := range map[string][]byte{
		"payload":     after.Payload,
		"wrapped key": after.WrappedDEK,
		"salt":        after.Salt,
		"meta":        after.MetaCT,
	} {
		if len(field) != 0 {
			t.Errorf("%s survived the claim; the record is still decryptable", name)
		}
	}
	if after.ConsumedAt.IsZero() {
		t.Error("consumed_at was not recorded")
	}

	// The receipt must learn about it too, so the sender sees the read.
	rec, err := s.LoadReceipt(ctx, "mid1")
	if err != nil {
		t.Fatalf("LoadReceipt: %v", err)
	}
	if rec.State != StateConsumed || rec.ConsumedAt.IsZero() {
		t.Fatalf("receipt not updated: %+v", rec)
	}

	// The tombstone must expire on its own rather than linger forever.
	if ttl := mr.TTL(SecretKey("sid1")); ttl <= 0 || ttl > time.Hour {
		t.Fatalf("tombstone TTL = %v, want (0, 1h]", ttl)
	}
}

func TestClaimSecretMissing(t *testing.T) {
	s, _ := newTestStore(t)
	claim, err := s.ClaimSecret(context.Background(), "ghost", "ghost", StateConsumed, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("ClaimSecret: %v", err)
	}
	if claim.Found || claim.Won {
		t.Fatalf("claim on a missing record returned %+v", claim)
	}
}

func TestExpiryRemovesSecretButKeepsReceipt(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	mr.FastForward(15 * 24 * time.Hour)

	if _, err := s.LoadSecret(ctx, "sid1"); err != ErrNotFound {
		t.Fatalf("expired secret error = %v, want ErrNotFound", err)
	}
	// The sender should still be able to see that nobody read it in time.
	if _, err := s.LoadReceipt(ctx, "mid1"); err != nil {
		t.Fatalf("receipt should outlive the secret, got %v", err)
	}
}

func TestMarkPeekedOnlyRecordsFirstVisit(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	first := time.Now().UTC().Truncate(time.Second)
	if err := s.MarkPeeked(ctx, "mid1", first); err != nil {
		t.Fatalf("MarkPeeked: %v", err)
	}
	if err := s.MarkPeeked(ctx, "mid1", first.Add(time.Hour)); err != nil {
		t.Fatalf("MarkPeeked again: %v", err)
	}
	rec, err := s.LoadReceipt(ctx, "mid1")
	if err != nil {
		t.Fatalf("LoadReceipt: %v", err)
	}
	if !rec.PeekedAt.Equal(first) {
		t.Fatalf("PeekedAt = %v, want the first visit at %v", rec.PeekedAt, first)
	}
}

func TestPassFailCounters(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	for i := 1; i <= 3; i++ {
		w, total, err := s.PassFail(ctx, "sid1", "mid1", 20*time.Minute, 14*24*time.Hour)
		if err != nil {
			t.Fatalf("PassFail: %v", err)
		}
		if w != i || total != i {
			t.Fatalf("attempt %d reported window=%d total=%d", i, w, total)
		}
	}
	n, err := s.PassFailCount(ctx, "sid1")
	if err != nil {
		t.Fatalf("PassFailCount: %v", err)
	}
	if n != 3 {
		t.Fatalf("PassFailCount = %d, want 3", n)
	}
	// The sender should be able to see that someone is guessing.
	rec, _ := s.LoadReceipt(ctx, "mid1")
	if rec.PassFails != 3 {
		t.Fatalf("receipt PassFails = %d, want 3", rec.PassFails)
	}
}

func TestTicketAttemptsAreBounded(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	tk := &Ticket{Blob: "abc123", FilenameCT: []byte("sealed-name"), PlainSize: 4242}
	if err := s.PutTicket(ctx, "tid1", tk, 5*time.Minute); err != nil {
		t.Fatalf("PutTicket: %v", err)
	}

	// A couple of retries are allowed: a download can drop halfway.
	for i := range 3 {
		got, err := s.ClaimTicket(ctx, "tid1", 3)
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		if got.Blob != "abc123" || got.PlainSize != 4242 {
			t.Fatalf("attempt %d returned %+v", i+1, got)
		}
	}
	// Beyond that the ticket is destroyed rather than becoming a download URL.
	if _, err := s.ClaimTicket(ctx, "tid1", 3); err != ErrTicketExhausted {
		t.Fatalf("error = %v, want ErrTicketExhausted", err)
	}
	if _, err := s.ClaimTicket(ctx, "tid1", 3); err != ErrNotFound {
		t.Fatalf("error after exhaustion = %v, want ErrNotFound", err)
	}
}

func TestRateLimitAllowsBurstThenThrottles(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	key := RateLimitKey("create", "client")
	const burst = 5
	interval := time.Second

	for i := range burst {
		ok, _, err := s.Allow(ctx, key, interval, burst)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !ok {
			t.Fatalf("request %d within the burst was denied", i+1)
		}
	}
	ok, retry, err := s.Allow(ctx, key, interval, burst)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if ok {
		t.Fatal("request past the burst was allowed")
	}
	if retry <= 0 {
		t.Fatalf("Retry-After = %v, want a positive duration", retry)
	}
}

func TestBlobScheduleAndCollect(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	if err := s.ScheduleBlob(ctx, "due", now.Add(-time.Minute)); err != nil {
		t.Fatalf("ScheduleBlob: %v", err)
	}
	if err := s.ScheduleBlob(ctx, "later", now.Add(time.Hour)); err != nil {
		t.Fatalf("ScheduleBlob: %v", err)
	}

	due, err := s.DueBlobs(ctx, now, 10)
	if err != nil {
		t.Fatalf("DueBlobs: %v", err)
	}
	if len(due) != 1 || due[0] != "due" {
		t.Fatalf("DueBlobs = %v, want [due]", due)
	}

	// Revealing a file pulls its deadline in; it must never push it out.
	if err := s.AdvanceBlobDeadline(ctx, "later", now.Add(time.Minute)); err != nil {
		t.Fatalf("AdvanceBlobDeadline: %v", err)
	}
	if err := s.AdvanceBlobDeadline(ctx, "later", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("AdvanceBlobDeadline: %v", err)
	}
	due, _ = s.DueBlobs(ctx, now.Add(2*time.Minute), 10)
	if len(due) != 2 {
		t.Fatalf("DueBlobs after advancing = %v, want both blobs due", due)
	}

	if err := s.ForgetBlob(ctx, "due", "later"); err != nil {
		t.Fatalf("ForgetBlob: %v", err)
	}
	due, _ = s.DueBlobs(ctx, now.Add(time.Hour), 10)
	if len(due) != 0 {
		t.Fatalf("DueBlobs after forgetting = %v, want empty", due)
	}
}

func TestDiskUsageAccounting(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if n, err := s.DiskUsage(ctx); err != nil || n != 0 {
		t.Fatalf("DiskUsage on a fresh store = %d, %v", n, err)
	}
	if err := s.AddDiskUsage(ctx, 1000); err != nil {
		t.Fatalf("AddDiskUsage: %v", err)
	}
	if err := s.AddDiskUsage(ctx, -400); err != nil {
		t.Fatalf("AddDiskUsage: %v", err)
	}
	if n, _ := s.DiskUsage(ctx); n != 600 {
		t.Fatalf("DiskUsage = %d, want 600", n)
	}
	// Reconcile walks the volume and overwrites the drifted counter.
	if err := s.SetDiskUsage(ctx, 42); err != nil {
		t.Fatalf("SetDiskUsage: %v", err)
	}
	if n, _ := s.DiskUsage(ctx); n != 42 {
		t.Fatalf("DiskUsage after reconcile = %d, want 42", n)
	}
}

func TestCheckActiveKeyIDDetectsVanishedKey(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if _, mismatch, err := s.CheckActiveKeyID(ctx, "v1", []string{"v1"}); err != nil || mismatch {
		t.Fatalf("first run reported mismatch=%v err=%v", mismatch, err)
	}
	// Rotating while keeping the old key around is a normal, safe operation.
	if _, mismatch, err := s.CheckActiveKeyID(ctx, "v2", []string{"v2", "v1"}); err != nil || mismatch {
		t.Fatalf("orderly rotation reported mismatch=%v err=%v", mismatch, err)
	}
	// Rotating to a ring that dropped the previous key strands every live
	// record, which is exactly what we want flagged.
	prev, mismatch, err := s.CheckActiveKeyID(ctx, "v3", []string{"v3"})
	if err != nil {
		t.Fatalf("CheckActiveKeyID: %v", err)
	}
	if !mismatch {
		t.Fatal("dropping the previous key was not flagged")
	}
	if prev != "v2" {
		t.Fatalf("previous key id = %q, want v2", prev)
	}
}

func TestKeyBuildersAreDistinct(t *testing.T) {
	id := "sameid"
	seen := map[string]string{}
	for name, key := range map[string]string{
		"secret":    SecretKey(id),
		"receipt":   ReceiptKey(id),
		"ticket":    TicketKey(id),
		"passfail":  PassFailKey(id),
		"passtotal": PassFailTotalKey(id),
	} {
		if other, dup := seen[key]; dup {
			t.Fatalf("%s and %s build the same Redis key %q", name, other, key)
		}
		seen[key] = name
	}
}

func TestSecretCountsSeparatesWaitingFromTombstones(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for _, id := range []string{"a", "b", "c"} {
		seedSecret(t, s, "sid"+id, "mid"+id)
	}
	// Consume one, leaving a tombstone behind.
	if _, err := s.ClaimSecret(ctx, "sida", "mida", StateConsumed, time.Now(), time.Hour); err != nil {
		t.Fatalf("ClaimSecret: %v", err)
	}

	waiting, tombstones, err := s.SecretCounts(ctx)
	if err != nil {
		t.Fatalf("SecretCounts: %v", err)
	}
	if waiting != 2 || tombstones != 1 {
		t.Fatalf("SecretCounts = %d waiting, %d tombstones; want 2 and 1", waiting, tombstones)
	}
}

func TestSecretCountsIgnoresOtherKeyspaces(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecret(t, s, "sid1", "mid1")

	// Receipts, tickets and limiter buckets share the prefix but must not be
	// counted as secrets.
	if err := s.PutTicket(ctx, "tid1", &Ticket{Blob: "x"}, time.Minute); err != nil {
		t.Fatalf("PutTicket: %v", err)
	}
	if _, _, err := s.Allow(ctx, RateLimitKey("create", "someone"), time.Second, 5); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	waiting, tombstones, err := s.SecretCounts(ctx)
	if err != nil {
		t.Fatalf("SecretCounts: %v", err)
	}
	if waiting != 1 || tombstones != 0 {
		t.Fatalf("SecretCounts = %d waiting, %d tombstones; want 1 and 0", waiting, tombstones)
	}
}
