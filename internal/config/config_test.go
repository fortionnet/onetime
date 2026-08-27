package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupEnv points configuration at a temporary directory and a literal keyring
// so that Load and Validate can run without a real deployment.
func setupEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ONETIME_MASTER_KEYS", "v1:"+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("ONETIME_BASE_URL", "https://onetime.example")
	t.Setenv("ONETIME_DATA_DIR", filepath.Join(dir, "blobs"))
	t.Setenv("ONETIME_TMP_DIR", filepath.Join(dir, "tmp"))
	return dir
}

func TestDefaults(t *testing.T) {
	setupEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// These three are the product decision the interface is built around:
	// retention is one to thirty days, and the default is fourteen so that most
	// people never have to open the options panel at all.
	if cfg.TTLMinDays != 1 || cfg.TTLMaxDays != 30 || cfg.TTLDefaultDays != 14 {
		t.Errorf("retention range = %d-%d default %d, want 1-30 default 14",
			cfg.TTLMinDays, cfg.TTLMaxDays, cfg.TTLDefaultDays)
	}
	if cfg.MaxFileBytes != 50<<20 {
		t.Errorf("MaxFileBytes = %d, want 50 MiB", cfg.MaxFileBytes)
	}
	if cfg.DefaultLang != "cs" {
		t.Errorf("DefaultLang = %q, want cs", cfg.DefaultLang)
	}
	if !cfg.EnableFiles || cfg.ReadOnly {
		t.Error("file sharing should be on and read-only off by default")
	}
	if cfg.Argon2MemKiB != 19456 || cfg.Argon2Time != 2 || cfg.Argon2Par != 1 {
		t.Errorf("Argon2 parameters %d/%d/%d do not match the OWASP minimum",
			cfg.Argon2MemKiB, cfg.Argon2Time, cfg.Argon2Par)
	}
}

func TestTTLFor(t *testing.T) {
	setupEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, tc := range []struct{ in, want int }{
		{0, 14},   // unspecified means the default
		{-5, 14},  // so does nonsense
		{1, 1},    // the floor
		{30, 30},  // the ceiling
		{100, 30}, // clamped, not rejected
		{7, 7},
	} {
		if got := cfg.TTLFor(tc.in); got != tc.want {
			t.Errorf("TTLFor(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestRejectsInconsistentSettings(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"retention floor above ceiling":   {"ONETIME_TTL_MIN_DAYS": "20", "ONETIME_TTL_MAX_DAYS": "10"},
		"default outside the range":       {"ONETIME_TTL_DEFAULT_DAYS": "99"},
		"zero retention floor":            {"ONETIME_TTL_MIN_DAYS": "0"},
		"unknown redis mode":              {"ONETIME_REDIS_MODE": "magic"},
		"external redis without a url":    {"ONETIME_REDIS_MODE": "external"},
		"unsupported language":            {"ONETIME_DEFAULT_LANG": "fr"},
		"base url without a scheme":       {"ONETIME_BASE_URL": "onetime.example"},
		"inline text limit above the cap": {"ONETIME_MAX_TEXT_INLINE_BYTES": "999999999"},
		"impossible watermark":            {"ONETIME_DISK_HIGH_WATERMARK_PCT": "150"},
		"unparsable duration":             {"ONETIME_GC_INTERVAL": "soon"},
		"unparsable number":               {"ONETIME_MAX_FILE_BYTES": "lots"},
	} {
		t.Run(name, func(t *testing.T) {
			setupEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load accepted an inconsistent configuration")
			}
		})
	}
}

func TestValidateRejectsSplitFilesystems(t *testing.T) {
	setupEnv(t)
	// /tmp is a separate filesystem from the test's temporary directory on
	// macOS, and on Linux the check simply passes; either way the point is that
	// Validate looks, because an atomic rename between them is what keeps a
	// half-written upload from being mistaken for a complete one.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate on a single filesystem: %v", err)
	}
}

func TestValidateRefusesUnwritableDataDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can write anywhere")
	}
	dir := setupEnv(t)
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Setenv("ONETIME_DATA_DIR", filepath.Join(blocked, "blobs"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a data directory it cannot write to")
	}
}

func TestMasterKeysPrefersTheFile(t *testing.T) {
	dir := setupEnv(t)
	keyFile := filepath.Join(dir, "master.keys")
	if err := os.WriteFile(keyFile, []byte("v2:from-the-file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("ONETIME_MASTER_KEYS", "")
	t.Setenv("ONETIME_MASTER_KEYS_FILE", keyFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := cfg.MasterKeys()
	if err != nil {
		t.Fatalf("MasterKeys: %v", err)
	}
	if got != "v2:from-the-file" {
		t.Fatalf("MasterKeys = %q, want the file contents trimmed", got)
	}
}

// TestStrictStartupRejectsWorldReadableKey covers a real deployment hazard:
// a keyring readable by other users on the node is a keyring that can be
// copied, and every secret ever written under it decrypted.
func TestStrictStartupRejectsWorldReadableKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, where file modes do not restrict access")
	}
	dir := setupEnv(t)
	keyFile := filepath.Join(dir, "master.keys")
	if err := os.WriteFile(keyFile, []byte("v1:key"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("ONETIME_MASTER_KEYS", "")
	t.Setenv("ONETIME_MASTER_KEYS_FILE", keyFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a group- and world-readable keyring")
	}

	// With the strict check off it is a warning, not a refusal, so an operator
	// who knows what they are doing is not blocked.
	t.Setenv("ONETIME_STRICT_STARTUP", "false")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate refused with the strict check disabled: %v", err)
	}
}

func TestEnvOverridesAreApplied(t *testing.T) {
	setupEnv(t)
	t.Setenv("ONETIME_TTL_DEFAULT_DAYS", "3")
	t.Setenv("ONETIME_MAX_FILE_BYTES", "1048576")
	t.Setenv("ONETIME_GC_INTERVAL", "90s")
	t.Setenv("ONETIME_ENABLE_FILES", "false")
	t.Setenv("ONETIME_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TTLDefaultDays != 3 || cfg.MaxFileBytes != 1<<20 || cfg.GCInterval != 90*time.Second {
		t.Fatalf("overrides not applied: %d %d %v", cfg.TTLDefaultDays, cfg.MaxFileBytes, cfg.GCInterval)
	}
	if cfg.EnableFiles {
		t.Error("ONETIME_ENABLE_FILES=false was ignored")
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("parsed %d trusted proxies, want 2", len(cfg.TrustedProxies))
	}
}

func TestBaseURLTrailingSlashIsDropped(t *testing.T) {
	setupEnv(t)
	t.Setenv("ONETIME_BASE_URL", "https://onetime.example/")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Links are built by concatenation, so a trailing slash here would produce
	// https://onetime.example//s/... in every link the service hands out.
	if cfg.BaseURL != "https://onetime.example" {
		t.Fatalf("BaseURL = %q, want the trailing slash removed", cfg.BaseURL)
	}
}

func TestRateLimitOverrides(t *testing.T) {
	setupEnv(t)
	t.Setenv("ONETIME_RATELIMIT_CREATE_TEXT", "500/50")
	t.Setenv("ONETIME_RATELIMIT_REVEAL", "1000/100")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, problems := cfg.RateLimitOverrides()
	if len(problems) != 0 {
		t.Fatalf("valid overrides reported problems: %v", problems)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d overrides, want 2: %+v", len(got), got)
	}
	if got["create_text"] != (RateLimit{PerHour: 500, Burst: 50}) {
		t.Fatalf("create_text = %+v, want 500/50", got["create_text"])
	}
	// Actions without an override must stay absent so the built-in default wins.
	if _, ok := got["peek"]; ok {
		t.Error("an action with no override was returned anyway")
	}
}

// TestRateLimitOverridesSurviveGarbage pins the decision that one mistyped
// limiter must not stop the service from starting: the bad value is reported
// and skipped, and the good ones still apply.
func TestRateLimitOverridesSurviveGarbage(t *testing.T) {
	setupEnv(t)
	t.Setenv("ONETIME_RATELIMIT_CREATE_TEXT", "not-a-limit")
	t.Setenv("ONETIME_RATELIMIT_PEEK", "100") // missing the burst
	t.Setenv("ONETIME_RATELIMIT_BURN", "0/5") // zero rate would block everything
	t.Setenv("ONETIME_RATELIMIT_REVEAL", "60/6")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, problems := cfg.RateLimitOverrides()
	if len(problems) != 3 {
		t.Fatalf("reported %d problems, want 3: %v", len(problems), problems)
	}
	if len(got) != 1 || got["reveal"] != (RateLimit{PerHour: 60, Burst: 6}) {
		t.Fatalf("the valid override did not survive: %+v", got)
	}
}

func TestNoRateLimitOverridesByDefault(t *testing.T) {
	setupEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, problems := cfg.RateLimitOverrides()
	if len(got) != 0 || len(problems) != 0 {
		t.Fatalf("a bare environment produced overrides %+v / problems %v", got, problems)
	}
}
