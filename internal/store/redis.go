package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed lua/claim_secret.lua
var claimSecretSrc string

//go:embed lua/claim_ticket.lua
var claimTicketSrc string

//go:embed lua/gcra.lua
var gcraSrc string

var (
	claimSecretScript = redis.NewScript(claimSecretSrc)
	claimTicketScript = redis.NewScript(claimTicketSrc)
	gcraScript        = redis.NewScript(gcraSrc)
)

// Redis is the persistence layer. It is a concrete type rather than an
// interface: there is one implementation, and tests run against miniredis,
// which speaks the same protocol.
type Redis struct {
	c redis.UniversalClient
}

// Options configures the client connection.
type Options struct {
	Mode     string // sidecar | external | none
	Addr     string
	URL      string
	Password string
	DB       int
}

// New connects to Redis. It does not verify reachability; call Ping for that.
func New(opts Options) (*Redis, error) {
	var ro *redis.Options
	if opts.URL != "" {
		parsed, err := redis.ParseURL(opts.URL)
		if err != nil {
			return nil, fmt.Errorf("store: parse redis url: %w", err)
		}
		ro = parsed
	} else {
		ro = &redis.Options{Addr: opts.Addr, DB: opts.DB}
	}
	if opts.Password != "" {
		ro.Password = opts.Password
	}
	return &Redis{c: redis.NewClient(ro)}, nil
}

// NewWithClient wraps an existing client, used by tests against miniredis.
func NewWithClient(c redis.UniversalClient) *Redis { return &Redis{c: c} }

// Close releases the connection pool.
func (r *Redis) Close() error { return r.c.Close() }

// Ping checks reachability.
func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }

// CheckEvictionPolicy verifies that Redis will not evict live secrets under
// memory pressure. With any allkeys-* policy, a busy instance silently deletes
// other people's unread secrets, which looks to them exactly like the service
// losing their data — because it is.
func (r *Redis) CheckEvictionPolicy(ctx context.Context) error {
	res, err := r.c.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		// miniredis and some managed providers do not expose CONFIG GET. An
		// unanswerable question is not a failed check: reporting it would fail
		// a strict startup on providers where the setting is fine but simply
		// not readable.
		//nolint:nilerr // an unanswerable check is not a failed check; see above
		return nil
	}
	policy, ok := res["maxmemory-policy"]
	if !ok || policy == "" || policy == "noeviction" {
		return nil
	}
	return fmt.Errorf("store: redis maxmemory-policy is %q, want noeviction: "+
		"any eviction policy will silently delete unread secrets", policy)
}

// CreateSecret writes the secret and its receipt together.
func (r *Redis) CreateSecret(ctx context.Context, sid, mid string, sec *Secret, rec *Receipt, secretTTL, receiptTTL time.Duration) error {
	sk, mk := SecretKey(sid), ReceiptKey(mid)
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, sk, sec.toMap())
	pipe.Expire(ctx, sk, secretTTL)
	pipe.HSet(ctx, mk, rec.toMap())
	pipe.Expire(ctx, mk, receiptTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store: create secret: %w", err)
	}
	return nil
}

// LoadSecret reads a record without consuming it. Reveal uses this to derive
// and verify the key before claiming, so a wrong passphrase never burns.
func (r *Redis) LoadSecret(ctx context.Context, sid string) (*Secret, error) {
	m, err := r.c.HGetAll(ctx, SecretKey(sid)).Result()
	if err != nil {
		return nil, fmt.Errorf("store: load secret: %w", err)
	}
	if len(m) == 0 {
		return nil, ErrNotFound
	}
	return secretFromMap(m), nil
}

// ClaimSecret consumes a secret exactly once. newState is StateConsumed for a
// normal reveal, StateBurned when the sender cancels, StateDestroyed after too
// many failed passphrase attempts.
func (r *Redis) ClaimSecret(ctx context.Context, sid, mid, newState string, now time.Time, tombstoneTTL time.Duration) (*Claim, error) {
	res, err := claimSecretScript.Run(ctx, r.c,
		[]string{SecretKey(sid), ReceiptKey(mid)},
		now.Unix(), int64(tombstoneTTL.Seconds()), newState,
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("store: claim secret: %w", err)
	}
	if len(res) == 0 {
		return nil, errors.New("store: claim secret returned nothing")
	}
	switch asString(res[0]) {
	case "GONE":
		return &Claim{Found: false}, nil
	case "LOST":
		state := ""
		if len(res) > 1 {
			state = asString(res[1])
		}
		return &Claim{Found: true, State: state}, nil
	case "OK":
		if len(res) < 6 {
			return nil, errors.New("store: claim secret returned a short result")
		}
		return &Claim{
			Won:       true,
			Found:     true,
			State:     newState,
			Kind:      asString(res[1]),
			Payload:   asBytes(res[2]),
			Blob:      asString(res[3]),
			MetaCT:    asBytes(res[4]),
			PlainSize: atoi64Or(asString(res[5]), 0),
		}, nil
	default:
		return nil, fmt.Errorf("store: claim secret returned %q", asString(res[0]))
	}
}

// LoadReceipt reads a sender's receipt.
func (r *Redis) LoadReceipt(ctx context.Context, mid string) (*Receipt, error) {
	m, err := r.c.HGetAll(ctx, ReceiptKey(mid)).Result()
	if err != nil {
		return nil, fmt.Errorf("store: load receipt: %w", err)
	}
	if len(m) == 0 {
		return nil, ErrNotFound
	}
	return receiptFromMap(m), nil
}

// MarkPeeked records the first time a recipient opened the link without
// revealing, which is how the sender sees "delivered but not read yet".
func (r *Redis) MarkPeeked(ctx context.Context, mid string, now time.Time) error {
	key := ReceiptKey(mid)
	existing, err := r.c.HGet(ctx, key, fPeekedAt).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("store: mark peeked: %w", err)
	}
	if existing != "" && existing != "0" {
		return nil
	}
	if err := r.c.HSet(ctx, key, fPeekedAt, now.Unix()).Err(); err != nil {
		return fmt.Errorf("store: mark peeked: %w", err)
	}
	return nil
}

// PassFail records a failed passphrase attempt and reports the count within the
// rolling window and over the secret's lifetime.
func (r *Redis) PassFail(ctx context.Context, sid, mid string, window, secretTTL time.Duration) (inWindow, total int, err error) {
	pipe := r.c.TxPipeline()
	w := pipe.Incr(ctx, PassFailKey(sid))
	pipe.Expire(ctx, PassFailKey(sid), window)
	t := pipe.Incr(ctx, PassFailTotalKey(sid))
	pipe.Expire(ctx, PassFailTotalKey(sid), secretTTL)
	pipe.HIncrBy(ctx, ReceiptKey(mid), fPassFails, 1)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, fmt.Errorf("store: record passphrase failure: %w", err)
	}
	return int(w.Val()), int(t.Val()), nil
}

// PassFailCount reports failures in the current window without recording one.
func (r *Redis) PassFailCount(ctx context.Context, sid string) (int, error) {
	n, err := r.c.Get(ctx, PassFailKey(sid)).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: read passphrase failures: %w", err)
	}
	return n, nil
}

// PutTicket stores a download authorisation. The data key is not in here — it
// travels inside the ticket itself, so a Redis dump taken during the ticket's
// short life still decrypts nothing.
func (r *Redis) PutTicket(ctx context.Context, tid string, t *Ticket, ttl time.Duration) error {
	key := TicketKey(tid)
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		fBlob:       t.Blob,
		fFilenameCT: t.FilenameCT,
		fPayloadAAD: t.PayloadAAD,
		fPlainSize:  t.PlainSize,
		fAttempts:   0,
	})
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store: put ticket: %w", err)
	}
	return nil
}

// ErrTicketExhausted means the ticket ran out of download attempts.
var ErrTicketExhausted = errors.New("store: download ticket exhausted")

// ClaimTicket validates a ticket and returns what to stream.
func (r *Redis) ClaimTicket(ctx context.Context, tid string, maxAttempts int) (*Ticket, error) {
	res, err := claimTicketScript.Run(ctx, r.c, []string{TicketKey(tid)}, maxAttempts).Slice()
	if err != nil {
		return nil, fmt.Errorf("store: claim ticket: %w", err)
	}
	if len(res) == 0 {
		return nil, errors.New("store: claim ticket returned nothing")
	}
	switch asString(res[0]) {
	case "GONE":
		return nil, ErrNotFound
	case "EXHAUSTED":
		return nil, ErrTicketExhausted
	case "OK":
		if len(res) < 5 {
			return nil, errors.New("store: claim ticket returned a short result")
		}
		return &Ticket{
			Blob:       asString(res[1]),
			FilenameCT: asBytes(res[2]),
			PayloadAAD: asBytes(res[3]),
			PlainSize:  atoi64Or(asString(res[4]), 0),
		}, nil
	default:
		return nil, fmt.Errorf("store: claim ticket returned %q", asString(res[0]))
	}
}

// DeleteTicket retires a ticket after a completed download.
func (r *Redis) DeleteTicket(ctx context.Context, tid string) error {
	return r.c.Del(ctx, TicketKey(tid)).Err()
}

// Allow applies the GCRA limiter. It returns whether the request may proceed
// and, if not, how long to wait.
func (r *Redis) Allow(ctx context.Context, key string, interval time.Duration, burst int) (bool, time.Duration, error) {
	if burst < 1 {
		burst = 1
	}
	// Burst tolerance is (burst-1) emission intervals, not burst: a client that
	// has spent nothing starts exactly one interval ahead of schedule, so
	// scaling by burst would let through burst+1 requests.
	burstMS := interval.Milliseconds() * int64(burst-1)
	res, err := gcraScript.Run(ctx, r.c, []string{key},
		time.Now().UnixMilli(), interval.Milliseconds(), burstMS).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("store: rate limit: %w", err)
	}
	if len(res) < 2 {
		return false, 0, errors.New("store: rate limit returned a short result")
	}
	allowed := atoi64Or(asString(res[0]), 0) == 1
	retry := time.Duration(atoi64Or(asString(res[1]), 0)) * time.Second
	return allowed, retry, nil
}

// AddDailyBytes accumulates an upload against a client's daily quota.
func (r *Redis) AddDailyBytes(ctx context.Context, identity string, day string, n int64) (int64, error) {
	key := DailyBytesKey(identity, day)
	pipe := r.c.TxPipeline()
	total := pipe.IncrBy(ctx, key, n)
	pipe.Expire(ctx, key, 48*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("store: daily quota: %w", err)
	}
	return total.Val(), nil
}

// ScheduleBlob registers a blob for collection at the given deadline.
func (r *Redis) ScheduleBlob(ctx context.Context, blobID string, deadline time.Time) error {
	return r.c.ZAdd(ctx, BlobGCKey(), redis.Z{Score: float64(deadline.Unix()), Member: blobID}).Err()
}

// AdvanceBlobDeadline pulls a blob's collection deadline earlier, never later.
func (r *Redis) AdvanceBlobDeadline(ctx context.Context, blobID string, deadline time.Time) error {
	return r.c.ZAddLT(ctx, BlobGCKey(), redis.Z{Score: float64(deadline.Unix()), Member: blobID}).Err()
}

// DueBlobs lists blobs whose deadline has passed.
func (r *Redis) DueBlobs(ctx context.Context, now time.Time, limit int64) ([]string, error) {
	return r.c.ZRangeByScore(ctx, BlobGCKey(), &redis.ZRangeBy{
		Min: "-inf", Max: itoa(now.Unix()), Count: limit,
	}).Result()
}

// ForgetBlob removes a blob from the collection schedule.
func (r *Redis) ForgetBlob(ctx context.Context, blobIDs ...string) error {
	if len(blobIDs) == 0 {
		return nil
	}
	members := make([]any, len(blobIDs))
	for i, id := range blobIDs {
		members[i] = id
	}
	return r.c.ZRem(ctx, BlobGCKey(), members...).Err()
}

// SecretExists reports whether a live record still references a blob. The GC
// uses it to decide whether a file on disk is still owned by anything.
func (r *Redis) SecretExists(ctx context.Context, sid string) (bool, error) {
	n, err := r.c.Exists(ctx, SecretKey(sid)).Result()
	if err != nil {
		return false, fmt.Errorf("store: exists: %w", err)
	}
	return n > 0, nil
}

// AddDiskUsage adjusts the running total of stored bytes.
func (r *Redis) AddDiskUsage(ctx context.Context, delta int64) error {
	return r.c.IncrBy(ctx, DiskUsageKey(), delta).Err()
}

// SetDiskUsage overwrites the running total, used by the reconcile pass which
// is authoritative because it walks the volume.
func (r *Redis) SetDiskUsage(ctx context.Context, total int64) error {
	return r.c.Set(ctx, DiskUsageKey(), total, 0).Err()
}

// DiskUsage reads the running total of stored bytes.
func (r *Redis) DiskUsage(ctx context.Context) (int64, error) {
	n, err := r.c.Get(ctx, DiskUsageKey()).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: disk usage: %w", err)
	}
	return n, nil
}

// CheckActiveKeyID compares the master key id in use against the one last
// recorded, and reports a mismatch. A silent change here means every live
// secret just became unreadable, so it is worth shouting about.
func (r *Redis) CheckActiveKeyID(ctx context.Context, keyID string, known []string) (previous string, mismatch bool, err error) {
	prev, err := r.c.Get(ctx, ActiveKeyIDKey()).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, r.c.Set(ctx, ActiveKeyIDKey(), keyID, 0).Err()
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read active key id: %w", err)
	}
	if prev != keyID {
		// A rotation is fine as long as the old key is still in the ring for
		// decryption; only a key that vanished entirely is a problem.
		stillKnown := false
		for _, id := range known {
			if id == prev {
				stillKnown = true
				break
			}
		}
		if err := r.c.Set(ctx, ActiveKeyIDKey(), keyID, 0).Err(); err != nil {
			return prev, !stillKnown, err
		}
		return prev, !stillKnown, nil
	}
	return prev, false, nil
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case int64:
		return itoa(t)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func asBytes(v any) []byte {
	s := asString(v)
	if s == "" {
		return nil
	}
	return []byte(s)
}

// BlobReferenced reports whether a live secret record still points at the given
// blob. The collector uses it as the single source of truth for whether a file
// on the volume is still owned by anything: consuming a secret clears the blob
// field, so a tombstone answers false and the file becomes collectable.
func (r *Redis) BlobReferenced(ctx context.Context, sid, blobID string) (bool, error) {
	got, err := r.c.HGet(ctx, SecretKey(sid), fBlob).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: blob reference: %w", err)
	}
	return got == blobID, nil
}

// SecretCounts reports how many secret records exist, split into those still
// waiting to be read and tombstones left behind by ones already consumed.
//
// This is a SCAN rather than a maintained counter on purpose. A counter would
// have to be decremented when a secret expires, but expiry is Redis deleting
// the key on its own schedule, which nothing observes — so the counter would
// drift upwards forever and the gauge would quietly stop meaning anything.
// Scanning is O(n) but runs once a minute against a keyspace measured in
// thousands, and it is always right.
func (r *Redis) SecretCounts(ctx context.Context) (waiting, tombstones int64, err error) {
	const batch = 500
	var cursor uint64
	for {
		keys, next, err := r.c.Scan(ctx, cursor, prefix+"s:*", batch).Result()
		if err != nil {
			return 0, 0, fmt.Errorf("store: scan secrets: %w", err)
		}
		if len(keys) > 0 {
			pipe := r.c.Pipeline()
			states := make([]*redis.StringCmd, len(keys))
			for i, key := range keys {
				states[i] = pipe.HGet(ctx, key, fState)
			}
			// Redis.Nil for a key that vanished mid-scan is expected, not an error.
			if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
				return 0, 0, fmt.Errorf("store: read secret states: %w", err)
			}
			for _, cmd := range states {
				switch state, err := cmd.Result(); {
				case err != nil:
					continue
				case state == StateNew:
					waiting++
				default:
					tombstones++
				}
			}
		}
		cursor = next
		if cursor == 0 {
			return waiting, tombstones, nil
		}
	}
}
