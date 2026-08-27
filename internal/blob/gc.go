package blob

import (
	"context"
	"log/slog"
	"time"
)

// Index is the part of the Redis store the collector needs. Keeping it narrow
// documents exactly how much authority the collector has over live data.
type Index interface {
	DueBlobs(ctx context.Context, now time.Time, limit int64) ([]string, error)
	ForgetBlob(ctx context.Context, blobIDs ...string) error
	ScheduleBlob(ctx context.Context, blobID string, deadline time.Time) error
	BlobReferenced(ctx context.Context, sid, blobID string) (bool, error)
	SetDiskUsage(ctx context.Context, total int64) error
	AddDiskUsage(ctx context.Context, delta int64) error
}

// Stats reports what a collection pass did, for metrics and logs.
type Stats struct {
	Deleted     int
	Orphans     int
	BytesFreed  int64
	Kept        int
	TotalBytes  int64
	TotalBlobs  int
	Rescheduled int
}

// Collector reclaims blobs whose secrets are gone.
//
// It runs two passes with different jobs. The sweep is cheap and frequent and
// works from the Redis schedule, so an expired or freshly burned file goes away
// within a minute. The reconcile is expensive and rare and works from the
// volume itself, which is the only thing that can recover after Redis is
// flushed or loses its append-only file — at that point the schedule is empty
// and every file on disk is an orphan nothing will ever ask for again.
type Collector struct {
	store  *Store
	index  Index
	log    *slog.Logger
	grace  time.Duration
	limit  int64
	onStat func(Stats)
}

// NewCollector wires a collector. grace is how long an unreferenced blob is
// left alone before deletion, which keeps the reconcile pass from deleting a
// file that is being uploaded right now.
func NewCollector(s *Store, idx Index, log *slog.Logger, grace time.Duration) *Collector {
	return &Collector{store: s, index: idx, log: log, grace: grace, limit: 500}
}

// OnStats registers a callback invoked after each pass, used to feed metrics.
func (c *Collector) OnStats(fn func(Stats)) { c.onStat = fn }

// Run drives both passes until the context is cancelled. It reconciles once at
// startup, because that is exactly when the volume and Redis are most likely to
// disagree.
func (c *Collector) Run(ctx context.Context, sweepEvery, reconcileEvery time.Duration) {
	if n, err := c.store.PurgeTmp(); err != nil {
		c.log.Warn("could not clear the staging directory", "error", err)
	} else if n > 0 {
		c.log.Info("cleared abandoned uploads from the staging directory", "files", n)
	}
	if stats, err := c.Reconcile(ctx, time.Now()); err != nil {
		c.log.Error("startup reconcile failed", "error", err)
	} else {
		c.report("reconcile", stats)
	}

	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	reconcile := time.NewTicker(reconcileEvery)
	defer reconcile.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			stats, err := c.Sweep(ctx, time.Now())
			if err != nil {
				c.log.Error("sweep failed", "error", err)
				continue
			}
			c.report("sweep", stats)
		case <-reconcile.C:
			stats, err := c.Reconcile(ctx, time.Now())
			if err != nil {
				c.log.Error("reconcile failed", "error", err)
				continue
			}
			c.report("reconcile", stats)
		}
	}
}

// Sweep deletes blobs whose scheduled deadline has passed and which no live
// secret still references.
func (c *Collector) Sweep(ctx context.Context, now time.Time) (Stats, error) {
	var stats Stats
	due, err := c.index.DueBlobs(ctx, now, c.limit)
	if err != nil {
		return stats, err
	}
	var forget []string
	for _, id := range due {
		referenced, err := c.referenced(ctx, id)
		if err != nil {
			c.log.Warn("could not check blob ownership", "blob", id, "error", err)
			continue
		}
		if referenced {
			// Still owned: its deadline arrived early because a reveal pulled it
			// in, but the download has not finished. Leave it for the next pass.
			stats.Kept++
			continue
		}
		freed, err := c.store.Delete(id)
		if err != nil {
			c.log.Warn("could not delete blob", "blob", id, "error", err)
			continue
		}
		stats.Deleted++
		stats.BytesFreed += freed
		forget = append(forget, id)
	}
	if len(forget) > 0 {
		if err := c.index.ForgetBlob(ctx, forget...); err != nil {
			return stats, err
		}
		if err := c.index.AddDiskUsage(ctx, -stats.BytesFreed); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

// Reconcile walks the volume and makes Redis agree with it.
func (c *Collector) Reconcile(ctx context.Context, now time.Time) (Stats, error) {
	var stats Stats
	err := c.store.Walk(func(e Entry) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		old := now.Sub(e.ModTime) > c.grace

		// A blob with no sidecar was interrupted between the two renames. Once
		// it is past the grace period nothing will ever claim it.
		if !e.HasMeta {
			if old {
				return c.drop(&stats, e, "no sidecar")
			}
			stats.Kept++
			return nil
		}
		if e.Sidecar.Expires > 0 && now.Unix() > e.Sidecar.Expires {
			return c.drop(&stats, e, "expired")
		}

		referenced, err := c.index.BlobReferenced(ctx, e.Sidecar.SecretID, e.ID)
		if err != nil {
			c.log.Warn("could not check blob ownership", "blob", e.ID, "error", err)
			stats.Kept++
			stats.TotalBytes += e.Size
			stats.TotalBlobs++
			return nil
		}
		if !referenced {
			if old {
				return c.drop(&stats, e, "unreferenced")
			}
			stats.Kept++
			stats.TotalBytes += e.Size
			stats.TotalBlobs++
			return nil
		}

		// Live blob: make sure it is on the schedule, in case the schedule was
		// lost with Redis.
		if e.Sidecar.Expires > 0 {
			if err := c.index.ScheduleBlob(ctx, e.ID, time.Unix(e.Sidecar.Expires, 0)); err == nil {
				stats.Rescheduled++
			}
		}
		stats.Kept++
		stats.TotalBytes += e.Size
		stats.TotalBlobs++
		return nil
	})
	if err != nil {
		return stats, err
	}
	// The walk just counted every byte on the volume, so it is authoritative:
	// overwrite the incrementally maintained counter rather than adjusting it.
	if err := c.index.SetDiskUsage(ctx, stats.TotalBytes); err != nil {
		return stats, err
	}
	return stats, nil
}

func (c *Collector) drop(stats *Stats, e Entry, reason string) error {
	freed, err := c.store.Delete(e.ID)
	if err != nil {
		c.log.Warn("could not delete blob", "blob", e.ID, "reason", reason, "error", err)
		return nil
	}
	stats.Deleted++
	stats.Orphans++
	stats.BytesFreed += freed
	c.log.Info("reclaimed an orphaned blob", "blob", e.ID, "reason", reason, "bytes", freed)
	return nil
}

func (c *Collector) referenced(ctx context.Context, id string) (bool, error) {
	meta, err := c.store.ReadSidecar(id)
	if err != nil {
		// No sidecar means nothing can own it.
		return false, nil
	}
	return c.index.BlobReferenced(ctx, meta.SecretID, id)
}

func (c *Collector) report(pass string, stats Stats) {
	if c.onStat != nil {
		c.onStat(stats)
	}
	if stats.Deleted == 0 && stats.Orphans == 0 {
		return
	}
	c.log.Info("collected blobs",
		"pass", pass, "deleted", stats.Deleted, "orphans", stats.Orphans, "bytes_freed", stats.BytesFreed)
}
