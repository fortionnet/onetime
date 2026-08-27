// Package observability wires logging, metrics and health checks.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds every collector the service exports.
//
// One rule governs the labels: none of them may be derived from user input.
// A label taken from a request path would both explode cardinality and write
// record identifiers into /metrics, which is a page we scrape and store.
type Metrics struct {
	SecretsCreated   *prometheus.CounterVec
	SecretsRevealed  *prometheus.CounterVec
	SecretsDestroyed *prometheus.CounterVec
	SecretsActive    prometheus.Gauge
	PassphraseFails  prometheus.Counter

	// LookupTotal counts record lookups by outcome. A rising bad_key rate is
	// the signature of someone trying to guess links.
	LookupTotal *prometheus.CounterVec

	// DecryptFailures is the most operationally important counter here. Any
	// non-zero unknown_key_id means a master key was rotated out from under
	// live records, and every one of those records is now unreadable forever.
	DecryptFailures *prometheus.CounterVec

	RateLimitHits *prometheus.CounterVec
	Rejected      *prometheus.CounterVec

	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec
	HTTPInflight prometheus.Gauge

	PayloadBytes  *prometheus.HistogramVec
	UploadBytes   prometheus.Counter
	DownloadBytes prometheus.Counter

	StorageBytes    prometheus.Gauge
	StorageFiles    prometheus.Gauge
	PVCFreeBytes    prometheus.Gauge
	DiskUsageRatio  prometheus.Gauge
	ReaperRuns      *prometheus.CounterVec
	ReaperOrphans   prometheus.Counter
	ReaperReclaimed prometheus.Counter

	RedisUp    prometheus.Gauge
	BuildInfo  *prometheus.GaugeVec
	Argon2Busy prometheus.Gauge
}

// NewMetrics registers the collectors on a registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	m := &Metrics{
		SecretsCreated: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_secrets_created_total",
			Help: "Secrets created, by payload kind and origin.",
		}, []string{"kind", "source"}),

		SecretsRevealed: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_secrets_revealed_total",
			Help: "Reveal attempts, by payload kind and outcome.",
		}, []string{"kind", "result"}),

		SecretsDestroyed: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_secrets_destroyed_total",
			Help: "Secrets destroyed, by reason.",
		}, []string{"reason"}),

		SecretsActive: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_secrets_active",
			Help: "Secrets currently stored and unread.",
		}),

		PassphraseFails: f.NewCounter(prometheus.CounterOpts{
			Name: "onetime_passphrase_failures_total",
			Help: "Failed passphrase attempts.",
		}),

		LookupTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_lookup_total",
			Help: "Record lookups by outcome; a rising bad_key rate suggests link guessing.",
		}, []string{"result"}),

		DecryptFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_decrypt_failures_total",
			Help: "Decryption failures by reason; unknown_key_id means a rotation stranded live records.",
		}, []string{"reason"}),

		RateLimitHits: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_ratelimit_hits_total",
			Help: "Requests refused by the rate limiter.",
		}, []string{"action", "scope"}),

		Rejected: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_rejected_total",
			Help: "Requests rejected before reaching the domain layer.",
		}, []string{"reason"}),

		HTTPRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_http_requests_total",
			Help: "HTTP requests by route template, method and status.",
		}, []string{"method", "route", "code"}),

		HTTPDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "onetime_http_request_duration_seconds",
			Help:    "HTTP request duration by route template.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"method", "route"}),

		HTTPInflight: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_http_inflight",
			Help: "HTTP requests currently being served.",
		}),

		PayloadBytes: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "onetime_payload_bytes",
			Help:    "Size of stored payloads.",
			Buckets: []float64{1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 5.24288e7},
		}, []string{"kind"}),

		UploadBytes: f.NewCounter(prometheus.CounterOpts{
			Name: "onetime_upload_bytes_total", Help: "Bytes accepted from uploads.",
		}),
		DownloadBytes: f.NewCounter(prometheus.CounterOpts{
			Name: "onetime_download_bytes_total", Help: "Bytes served to downloads.",
		}),

		StorageBytes: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_storage_bytes", Help: "Bytes of encrypted payload on the volume.",
		}),
		StorageFiles: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_storage_files", Help: "Encrypted payload files on the volume.",
		}),
		PVCFreeBytes: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_pvc_free_bytes", Help: "Free bytes on the volume.",
		}),
		DiskUsageRatio: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_disk_usage_ratio", Help: "Fraction of the volume in use.",
		}),

		ReaperRuns: f.NewCounterVec(prometheus.CounterOpts{
			Name: "onetime_reaper_runs_total", Help: "Garbage collection passes by result.",
		}, []string{"result"}),
		ReaperOrphans: f.NewCounter(prometheus.CounterOpts{
			Name: "onetime_reaper_orphans_deleted_total",
			Help: "Blobs deleted because nothing referenced them.",
		}),
		ReaperReclaimed: f.NewCounter(prometheus.CounterOpts{
			Name: "onetime_reaper_bytes_reclaimed_total", Help: "Bytes reclaimed by the collector.",
		}),

		RedisUp: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_redis_up", Help: "Whether Redis answered its last health check.",
		}),
		BuildInfo: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "onetime_build_info", Help: "Build information; always 1.",
		}, []string{"version", "commit", "goversion"}),
		Argon2Busy: f.NewGauge(prometheus.GaugeOpts{
			Name: "onetime_argon2_inflight", Help: "Argon2id derivations in progress.",
		}),
	}
	return m
}

// SetBuildInfo records the running build.
func (m *Metrics) SetBuildInfo(version, commit, goVersion string) {
	m.BuildInfo.WithLabelValues(version, commit, goVersion).Set(1)
}
