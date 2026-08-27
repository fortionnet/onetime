// Package config loads and validates runtime configuration from the environment.
//
// Every knob is an ONETIME_* environment variable. Secret material (the master
// keyring, the Redis password) is read from files rather than the environment,
// because environment values leak through /proc/<pid>/environ, crash dumps and
// `kubectl describe pod`.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	ListenAddr  string
	MetricsAddr string
	BaseURL     string

	RedisMode         string // sidecar | external | none
	RedisAddr         string
	RedisURL          string
	RedisPasswordFile string
	RedisDB           int

	MasterKeysFile string
	MasterKeysRaw  string

	DataDir string
	TmpDir  string

	MaxFileBytes       int64
	MaxTextInlineBytes int64
	MaxTextBytes       int64

	TTLMinDays     int
	TTLMaxDays     int
	TTLDefaultDays int

	ReceiptExtraTTL   time.Duration
	TombstoneTTL      time.Duration
	DownloadTicketTTL time.Duration
	DownloadAttempts  int

	Argon2MemKiB      uint32
	Argon2Time        uint32
	Argon2Par         uint8
	Argon2Concurrency int

	PassphraseWindowFails int
	PassphraseWindow      time.Duration
	PassphraseTotalFails  int

	DiskHighWatermarkPct int
	DailyBytesPerIP      int64
	TotalStorageBytes    int64

	TrustedProxies []netip.Prefix

	GCInterval        time.Duration
	ReconcileInterval time.Duration
	OrphanGrace       time.Duration

	EnableFiles bool
	ReadOnly    bool

	DefaultLang string
	LogLevel    string
	LogFormat   string

	ShutdownTimeout time.Duration
	StrictStartup   bool

	RateLimitEnabled bool
}

// Load reads configuration from the environment and applies defaults. It does
// not touch the filesystem or the network; call Validate for that.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:  env("ONETIME_LISTEN_ADDR", ":8080"),
		MetricsAddr: env("ONETIME_METRICS_ADDR", ":9090"),
		BaseURL:     strings.TrimRight(env("ONETIME_BASE_URL", "http://localhost:8080"), "/"),

		RedisMode:         env("ONETIME_REDIS_MODE", "sidecar"),
		RedisAddr:         env("ONETIME_REDIS_ADDR", "127.0.0.1:6379"),
		RedisURL:          env("ONETIME_REDIS_URL", ""),
		RedisPasswordFile: env("ONETIME_REDIS_PASSWORD_FILE", ""),

		MasterKeysFile: env("ONETIME_MASTER_KEYS_FILE", "/run/secrets/onetime/master.keys"),
		MasterKeysRaw:  env("ONETIME_MASTER_KEYS", ""),

		DataDir: env("ONETIME_DATA_DIR", "/data/blobs"),
		TmpDir:  env("ONETIME_TMP_DIR", "/data/tmp"),

		DefaultLang: env("ONETIME_DEFAULT_LANG", "cs"),
		LogLevel:    env("ONETIME_LOG_LEVEL", "info"),
		LogFormat:   env("ONETIME_LOG_FORMAT", "json"),
	}

	var err error
	ints := []struct {
		dst *int
		key string
		def int
	}{
		{&c.RedisDB, "ONETIME_REDIS_DB", 0},
		{&c.TTLMinDays, "ONETIME_TTL_MIN_DAYS", 1},
		{&c.TTLMaxDays, "ONETIME_TTL_MAX_DAYS", 30},
		{&c.TTLDefaultDays, "ONETIME_TTL_DEFAULT_DAYS", 14},
		{&c.Argon2Concurrency, "ONETIME_ARGON2_CONCURRENCY", 4},
		{&c.PassphraseWindowFails, "ONETIME_PASSPHRASE_WINDOW_FAILS", 5},
		{&c.PassphraseTotalFails, "ONETIME_PASSPHRASE_TOTAL_FAILS", 20},
		{&c.DiskHighWatermarkPct, "ONETIME_DISK_HIGH_WATERMARK_PCT", 85},
		{&c.DownloadAttempts, "ONETIME_DOWNLOAD_ATTEMPTS", 3},
	}
	for _, it := range ints {
		if *it.dst, err = envInt(it.key, it.def); err != nil {
			return nil, err
		}
	}

	i64s := []struct {
		dst *int64
		key string
		def int64
	}{
		{&c.MaxFileBytes, "ONETIME_MAX_FILE_BYTES", 50 << 20},
		{&c.MaxTextInlineBytes, "ONETIME_MAX_TEXT_INLINE_BYTES", 100 << 10},
		{&c.MaxTextBytes, "ONETIME_MAX_TEXT_BYTES", 1 << 20},
		{&c.DailyBytesPerIP, "ONETIME_DAILY_BYTES_PER_IP", 500 << 20},
		{&c.TotalStorageBytes, "ONETIME_TOTAL_STORAGE_BYTES", 20 << 30},
	}
	for _, it := range i64s {
		if *it.dst, err = envInt64(it.key, it.def); err != nil {
			return nil, err
		}
	}

	durs := []struct {
		dst *time.Duration
		key string
		def time.Duration
	}{
		{&c.ReceiptExtraTTL, "ONETIME_RECEIPT_EXTRA_TTL", 168 * time.Hour},
		{&c.TombstoneTTL, "ONETIME_TOMBSTONE_TTL", 24 * time.Hour},
		{&c.DownloadTicketTTL, "ONETIME_DOWNLOAD_TICKET_TTL", 5 * time.Minute},
		{&c.PassphraseWindow, "ONETIME_PASSPHRASE_WINDOW", 20 * time.Minute},
		{&c.GCInterval, "ONETIME_GC_INTERVAL", time.Minute},
		{&c.ReconcileInterval, "ONETIME_RECONCILE_INTERVAL", 6 * time.Hour},
		{&c.OrphanGrace, "ONETIME_ORPHAN_GRACE", time.Hour},
		{&c.ShutdownTimeout, "ONETIME_SHUTDOWN_TIMEOUT", 60 * time.Second},
	}
	for _, it := range durs {
		if *it.dst, err = envDur(it.key, it.def); err != nil {
			return nil, err
		}
	}

	// OWASP minimum for Argon2id: 19 MiB, t=2, p=1.
	mem, err := envInt("ONETIME_ARGON2_MEM_KIB", 19456)
	if err != nil {
		return nil, err
	}
	tm, err := envInt("ONETIME_ARGON2_TIME", 2)
	if err != nil {
		return nil, err
	}
	par, err := envInt("ONETIME_ARGON2_PAR", 1)
	if err != nil {
		return nil, err
	}
	c.Argon2MemKiB, c.Argon2Time, c.Argon2Par = uint32(mem), uint32(tm), uint8(par)

	c.EnableFiles = envBool("ONETIME_ENABLE_FILES", true)
	c.ReadOnly = envBool("ONETIME_READ_ONLY", false)
	c.StrictStartup = envBool("ONETIME_STRICT_STARTUP", true)
	c.RateLimitEnabled = envBool("ONETIME_RATELIMIT_ENABLED", true)

	if c.TrustedProxies, err = envPrefixes("ONETIME_TRUSTED_PROXIES"); err != nil {
		return nil, err
	}
	return c, c.check()
}

// check validates values that do not require touching the filesystem.
func (c *Config) check() error {
	switch c.RedisMode {
	case "sidecar", "external", "none":
	default:
		return fmt.Errorf("ONETIME_REDIS_MODE: want sidecar|external|none, got %q", c.RedisMode)
	}
	if c.RedisMode == "external" && c.RedisURL == "" {
		return fmt.Errorf("ONETIME_REDIS_URL is required when ONETIME_REDIS_MODE=external")
	}
	if c.TTLMinDays < 1 {
		return fmt.Errorf("ONETIME_TTL_MIN_DAYS must be >= 1, got %d", c.TTLMinDays)
	}
	if c.TTLMaxDays < c.TTLMinDays {
		return fmt.Errorf("ONETIME_TTL_MAX_DAYS (%d) must be >= ONETIME_TTL_MIN_DAYS (%d)", c.TTLMaxDays, c.TTLMinDays)
	}
	if c.TTLDefaultDays < c.TTLMinDays || c.TTLDefaultDays > c.TTLMaxDays {
		return fmt.Errorf("ONETIME_TTL_DEFAULT_DAYS (%d) must be within [%d,%d]", c.TTLDefaultDays, c.TTLMinDays, c.TTLMaxDays)
	}
	if c.MaxFileBytes < 1 {
		return fmt.Errorf("ONETIME_MAX_FILE_BYTES must be positive, got %d", c.MaxFileBytes)
	}
	if c.MaxTextInlineBytes > c.MaxTextBytes {
		return fmt.Errorf("ONETIME_MAX_TEXT_INLINE_BYTES (%d) must be <= ONETIME_MAX_TEXT_BYTES (%d)", c.MaxTextInlineBytes, c.MaxTextBytes)
	}
	if c.DiskHighWatermarkPct < 1 || c.DiskHighWatermarkPct > 100 {
		return fmt.Errorf("ONETIME_DISK_HIGH_WATERMARK_PCT must be within [1,100], got %d", c.DiskHighWatermarkPct)
	}
	if c.Argon2Concurrency < 1 {
		return fmt.Errorf("ONETIME_ARGON2_CONCURRENCY must be >= 1, got %d", c.Argon2Concurrency)
	}
	if c.DefaultLang != "cs" && c.DefaultLang != "en" {
		return fmt.Errorf("ONETIME_DEFAULT_LANG: want cs|en, got %q", c.DefaultLang)
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("ONETIME_BASE_URL must start with http:// or https://, got %q", c.BaseURL)
	}
	return nil
}

// TTLFor clamps a requested retention in days into the configured range. A
// non-positive request means "use the default".
func (c *Config) TTLFor(days int) int {
	if days <= 0 {
		return c.TTLDefaultDays
	}
	return min(max(days, c.TTLMinDays), c.TTLMaxDays)
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envInt64(key string, def int64) (int64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDur(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envPrefixes(key string) ([]netip.Prefix, error) {
	v := os.Getenv(key)
	if v == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, raw := range strings.Split(v, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", key, raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// RateLimits holds per-action allowances parsed from the environment.
//
// Each entry is "<per-hour>/<burst>", e.g. "30/10". A missing or malformed
// value falls back to the built-in default rather than failing the start:
// a typo in one limiter should not take the service down.
type RateLimits map[string]RateLimit

// RateLimit is one action's allowance.
type RateLimit struct {
	PerHour int
	Burst   int
}

// rateLimitEnv maps an action name to the variable that overrides it.
var rateLimitEnv = map[string]string{
	"create_text": "ONETIME_RATELIMIT_CREATE_TEXT",
	"create_file": "ONETIME_RATELIMIT_CREATE_FILE",
	"generate":    "ONETIME_RATELIMIT_GENERATE",
	"peek":        "ONETIME_RATELIMIT_PEEK",
	"reveal":      "ONETIME_RATELIMIT_REVEAL",
	"download":    "ONETIME_RATELIMIT_DOWNLOAD",
	"receipt":     "ONETIME_RATELIMIT_RECEIPT",
	"burn":        "ONETIME_RATELIMIT_BURN",
	"page":        "ONETIME_RATELIMIT_PAGE",
}

// RateLimitOverrides reads the per-action overrides that are present.
//
// These matter more than they look. The limiter counts per client address, and
// a whole office behind one NAT gateway is a single address — so a deployment
// serving business customers may legitimately need far higher numbers than a
// public one. Without this, tuning them means rebuilding the binary.
func (c *Config) RateLimitOverrides() (RateLimits, []error) {
	out := make(RateLimits)
	var problems []error
	for action, key := range rateLimitEnv {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		limit, err := parseRateLimit(raw)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", key, err))
			continue
		}
		out[action] = limit
	}
	return out, problems
}

func parseRateLimit(raw string) (RateLimit, error) {
	perHour, burst, ok := strings.Cut(raw, "/")
	if !ok {
		return RateLimit{}, fmt.Errorf("want <per-hour>/<burst>, got %q", raw)
	}
	n, err := strconv.Atoi(strings.TrimSpace(perHour))
	if err != nil || n < 1 {
		return RateLimit{}, fmt.Errorf("per-hour must be a positive number, got %q", perHour)
	}
	b, err := strconv.Atoi(strings.TrimSpace(burst))
	if err != nil || b < 1 {
		return RateLimit{}, fmt.Errorf("burst must be a positive number, got %q", burst)
	}
	return RateLimit{PerHour: n, Burst: b}, nil
}
