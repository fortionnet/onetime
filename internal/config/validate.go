package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Validate performs the fail-fast startup checks that need the filesystem. It
// deliberately runs before the server binds, so a misconfigured deployment
// crashes loudly instead of silently losing secrets.
func (c *Config) Validate() error {
	if err := c.validateKeyFile(); err != nil {
		return err
	}
	if !c.EnableFiles {
		return nil
	}
	for _, dir := range []string{c.DataDir, c.TmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := probeWritable(dir); err != nil {
			return err
		}
	}
	// An atomic rename from TmpDir into DataDir is the backbone of blob writes,
	// and rename only works within a single filesystem.
	if same, err := sameDevice(c.DataDir, c.TmpDir); err != nil {
		return err
	} else if !same {
		return fmt.Errorf("ONETIME_DATA_DIR (%s) and ONETIME_TMP_DIR (%s) must be on the same filesystem: "+
			"blob writes rely on an atomic rename between them", c.DataDir, c.TmpDir)
	}
	return nil
}

// MasterKeys returns the raw keyring string, preferring the file over the
// environment variable. Format: "v2:<base64>,v1:<base64>", newest key first.
func (c *Config) MasterKeys() (string, error) {
	if c.MasterKeysRaw != "" {
		return c.MasterKeysRaw, nil
	}
	b, err := os.ReadFile(c.MasterKeysFile)
	if err != nil {
		return "", fmt.Errorf("read master keyring %s: %w", c.MasterKeysFile, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Config) validateKeyFile() error {
	if c.MasterKeysRaw != "" {
		return nil // explicit override, used by tests and local dev
	}
	fi, err := os.Stat(c.MasterKeysFile)
	if err != nil {
		return fmt.Errorf("master keyring: %w (set ONETIME_MASTER_KEYS_FILE or ONETIME_MASTER_KEYS)", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("master keyring %s is a directory", c.MasterKeysFile)
	}
	if perm := fi.Mode().Perm(); c.StrictStartup && perm&0o077 != 0 {
		return fmt.Errorf("master keyring %s has mode %#o; must not be readable by group or other", c.MasterKeysFile, perm)
	}
	return nil
}

func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".rw-probe-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	name := f.Name()
	err = errors.Join(f.Close(), os.Remove(name))
	if err != nil {
		return fmt.Errorf("%s probe cleanup: %w", dir, err)
	}
	return nil
}

func sameDevice(a, b string) (bool, error) {
	da, err := deviceOf(a)
	if err != nil {
		return false, err
	}
	db, err := deviceOf(b)
	if err != nil {
		return false, err
	}
	return da == db, nil
}

func deviceOf(path string) (uint64, error) {
	fi, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, nil // unknown platform: skip the check rather than fail
	}
	return uint64(st.Dev), nil
}
