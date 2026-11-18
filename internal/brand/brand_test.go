package brand

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBrand(t *testing.T, dir, config string, files map[string]string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDefaultLoads(t *testing.T) {
	b, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if b.Name == "" || b.Logo.File == "" || b.Favicon == "" {
		t.Errorf("default brand is incomplete: %+v", b)
	}
	if _, ok := b.Files()[b.Logo.File]; !ok {
		t.Errorf("default logo %q not loaded", b.Logo.File)
	}
	if b.TextFor("en")["operator"] == "" {
		t.Error("default brand has no English operator line")
	}
}

func TestLoadEmptyDirIsDefault(t *testing.T) {
	b, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := Default()
	if b.Name != d.Name {
		t.Errorf("Load(\"\") = %q, want the default %q", b.Name, d.Name)
	}
}

func TestLoadCustomBrand(t *testing.T) {
	dir := t.TempDir()
	writeBrand(t, dir, `{
		"name": "Example Corp",
		"url": "https://www.example.com",
		"logo": {"file": "logo.png", "width": 200, "height": 40},
		"stylesheet": "brand.css",
		"fonts": {"stylesheet": "https://fonts.example.net/css?family=X",
		          "fontOrigins": ["https://static.example.net"]},
		"text": {"cs": {"operator": "Provozuje Example"}},
		"messages": {"en": {"site.name": "secrets"}}
	}`, map[string]string{"logo.png": "png", "brand.css": ":root{--brand:red}"})

	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Host() != "example.com" {
		t.Errorf("Host = %q", b.Host())
	}
	if got := b.StyleOrigins(); len(got) != 1 || got[0] != "https://fonts.example.net" {
		t.Errorf("StyleOrigins = %v", got)
	}
	if got := b.FontOrigins(); len(got) != 1 || got[0] != "https://static.example.net" {
		t.Errorf("FontOrigins = %v", got)
	}
	// English falls back to the Czech operator line rather than to nothing.
	if got := b.TextFor("en")["operator"]; got != "Provozuje Example" {
		t.Errorf("TextFor(en) operator = %q", got)
	}
	if _, ok := b.TextFor("en")["operator_ids"]; ok {
		t.Error("a key the brand does not define must be absent")
	}
}

// A mounted ConfigMap exposes each key as a symlink into a hidden "..data"
// directory. The loader has to follow the symlinks and skip the dot entries.
func TestLoadConfigMapLayout(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "..2026_11_18_00_00_00.000000000")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBrand(t, data, `{"name": "CM", "logo": {"file": "logo.svg", "width": 1, "height": 1}}`,
		map[string]string{"logo.svg": "<svg/>"})
	if err := os.Symlink(filepath.Base(data), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ConfigFile, "logo.svg"} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(b.Files()) != 1 || string(b.Files()["logo.svg"]) != "<svg/>" {
		t.Errorf("Files = %v", b.Files())
	}
}

func TestLoadRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		files  map[string]string
		want   string
	}{
		{"no name", `{}`, nil, "name is required"},
		{"unknown field", `{"name": "x", "colour": "red"}`, nil, "unknown field"},
		{"missing logo file", `{"name": "x", "logo": {"file": "logo.svg", "width": 1, "height": 1}}`, nil,
			"not in the brand directory"},
		{"logo without size", `{"name": "x", "logo": {"file": "logo.svg"}}`,
			map[string]string{"logo.svg": "<svg/>"}, "logo.width"},
		{"script in the directory", `{"name": "x"}`, map[string]string{"evil.js": "alert(1)"},
			"file type not allowed"},
		{"stylesheet that is not css", `{"name": "x", "stylesheet": "logo.svg"}`,
			map[string]string{"logo.svg": "<svg/>"}, "stylesheet"},
		{"http font stylesheet", `{"name": "x", "fonts": {"stylesheet": "http://fonts.example/css"}}`, nil,
			"https"},
		{"font origin with a path", `{"name": "x", "fonts": {"fontOrigins": ["https://f.example/x"]}}`, nil,
			"origin"},
		{"font origin breaking the CSP", `{"name": "x", "fonts": {"fontOrigins": ["https://a;script-src *"]}}`, nil,
			"fontOrigins"},
		{"javascript url", `{"name": "x", "url": "javascript:alert(1)"}`, nil, "url"},
		{"unknown text key", `{"name": "x", "text": {"cs": {"operater": "y"}}}`, nil, "unknown key"},
		{"unsupported text language", `{"name": "x", "text": {"de": {"operator": "y"}}}`, nil, "unsupported"},
		{"unknown message key", `{"name": "x", "messages": {"cs": {"no.such.key": "y"}}}`, nil, "unknown key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBrand(t, dir, tc.config, tc.files)
			_, err := Load(dir)
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadMissingConfig(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("a directory without brand.json must not load")
	}
}
