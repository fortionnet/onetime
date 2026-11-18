// Package brand loads the identity an instance presents: the operator's name,
// logo, favicon, optional stylesheet and fonts, and the operator's legal text.
//
// Nothing brand-specific lives in the templates, the stylesheet or the message
// catalogue. A brand is a directory holding brand.json and the files it names;
// the default one is compiled into the binary (web/brand), and an operator
// replaces it as a whole by pointing ONETIME_BRAND_DIR at a directory of the
// same shape — typically a ConfigMap mounted by the Helm chart.
//
// Replacement is whole, not per file. A partial overlay would let a rebranded
// instance silently fall back to someone else's logo or legal address because
// one file was missing from a ConfigMap; with a whole replacement a missing
// file is simply absent, and anything brand.json names but the directory lacks
// is a startup error.
package brand

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	webassets "github.com/fortionnet/onetime/web"

	"github.com/fortionnet/onetime/internal/i18n"
)

// ConfigFile is the name of the brand description inside a brand directory.
const ConfigFile = "brand.json"

// MaxFileBytes caps each brand file. The files are read into memory at startup
// and a Kubernetes ConfigMap holds at most 1 MiB in total anyway.
const MaxFileBytes = 1 << 20

// allowedExt lists what a brand directory may contain besides brand.json.
// Everything is served same-origin under /static/brand/, so the list is kept to
// passive formats: no HTML, no JavaScript.
var allowedExt = map[string]bool{
	".svg": true, ".png": true, ".webp": true, ".ico": true,
	".css": true, ".woff2": true,
}

// TextKeys are the per-language strings a brand supplies about its operator.
// Each is optional; the templates leave out whatever is missing.
var TextKeys = []string{
	"operator",         // one line in the footer
	"operator_legal",   // who runs the service, on the privacy page
	"operator_address", // registered address, on the privacy page
	"operator_ids",     // company / VAT identifiers, on the privacy page
}

// Brand is a loaded and validated brand.
type Brand struct {
	// Name is the operator's name, used in the logo link's accessible label
	// and as the visible mark when there is no logo.
	Name string `json:"name"`
	// URL is the operator's website, which the logo links to. Optional.
	URL string `json:"url"`
	// Logo is the header image. Optional; without it the name is shown.
	Logo Logo `json:"logo"`
	// Favicon is a file in the brand directory. Optional.
	Favicon string `json:"favicon"`
	// Stylesheet is a CSS file in the brand directory, linked after the
	// application stylesheet. It is meant to redefine the :root tokens
	// (--brand*, --accent*, --font-*). Optional.
	Stylesheet string `json:"stylesheet"`
	// Fonts is an optional external font stylesheet and the origins its font
	// files come from; both are added to the content security policy.
	Fonts Fonts `json:"fonts"`
	// Text holds TextKeys per language.
	Text map[string]map[string]string `json:"text"`
	// Messages overrides entries of the message catalogue per language. Only
	// keys the catalogue already defines are accepted.
	Messages map[string]map[string]string `json:"messages"`

	files map[string][]byte
}

// Logo is the header image and its intrinsic size, which the page reserves
// before the image loads so the header does not jump.
type Logo struct {
	File   string `json:"file"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// Fonts describes an external font stylesheet.
type Fonts struct {
	// Stylesheet is an https URL, e.g. a Google Fonts css2 link.
	Stylesheet string `json:"stylesheet"`
	// FontOrigins are the https origins the stylesheet loads font files from.
	FontOrigins []string `json:"fontOrigins"`
}

// Load reads the brand from dir, or the compiled-in default when dir is empty.
func Load(dir string) (*Brand, error) {
	if dir == "" {
		return Default()
	}
	b, err := load(os.DirFS(dir))
	if err != nil {
		return nil, fmt.Errorf("brand: %s: %w", dir, err)
	}
	return b, nil
}

// Default returns the brand compiled into the binary.
func Default() (*Brand, error) {
	sub, err := fs.Sub(webassets.Brand, "brand")
	if err != nil {
		return nil, err
	}
	b, err := load(sub)
	if err != nil {
		return nil, fmt.Errorf("brand: embedded default: %w", err)
	}
	return b, nil
}

func load(fsys fs.FS) (*Brand, error) {
	raw, err := fs.ReadFile(fsys, ConfigFile)
	if err != nil {
		return nil, err
	}
	b := &Brand{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if decErr := dec.Decode(b); decErr != nil {
		return nil, fmt.Errorf("%s: %w", ConfigFile, decErr)
	}
	if b.files, err = readFiles(fsys); err != nil {
		return nil, err
	}
	if err = b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// readFiles reads the top level of a brand directory. Dot entries are skipped:
// a mounted ConfigMap keeps its real content in "..data" and timestamped
// "..2026_…" directories, and exposes each key as a symlink beside them.
func readFiles(fsys fs.FS) (map[string][]byte, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == ConfigFile {
			continue
		}
		info, err := fs.Stat(fsys, name) // follows the ConfigMap symlinks
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		if !allowedExt[strings.ToLower(path.Ext(name))] {
			return nil, fmt.Errorf("%s: file type not allowed (allowed: %s)", name, allowedList())
		}
		if info.Size() > MaxFileBytes {
			return nil, fmt.Errorf("%s: %d bytes, limit is %d", name, info.Size(), MaxFileBytes)
		}
		if files[name], err = fs.ReadFile(fsys, name); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func allowedList() string {
	out := make([]string, 0, len(allowedExt))
	for ext := range allowedExt {
		out = append(out, ext)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func (b *Brand) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if strings.TrimSpace(b.Name) == "" {
		fail("name is required")
	}
	if b.URL != "" {
		if u, err := url.Parse(b.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			fail("url %q must be an absolute http(s) URL", b.URL)
		}
	}

	needFile := func(field, name string, exts ...string) {
		if name == "" {
			return
		}
		if _, ok := b.files[name]; !ok {
			fail("%s names %q, which is not in the brand directory", field, name)
			return
		}
		ext := strings.ToLower(path.Ext(name))
		for _, e := range exts {
			if ext == e {
				return
			}
		}
		fail("%s %q must be one of %v", field, name, exts)
	}
	needFile("logo.file", b.Logo.File, ".svg", ".png", ".webp")
	needFile("favicon", b.Favicon, ".svg", ".png", ".ico")
	needFile("stylesheet", b.Stylesheet, ".css")
	if b.Logo.File != "" && (b.Logo.Width <= 0 || b.Logo.Height <= 0) {
		fail("logo.width and logo.height are required with logo.file")
	}

	if b.Fonts.Stylesheet != "" {
		if _, err := originOf(b.Fonts.Stylesheet, true); err != nil {
			fail("fonts.stylesheet: %v", err)
		}
	}
	for _, o := range b.Fonts.FontOrigins {
		if _, err := originOf(o, false); err != nil {
			fail("fonts.fontOrigins: %v", err)
		}
	}

	known := map[string]bool{}
	for _, k := range TextKeys {
		known[k] = true
	}
	for lang, m := range b.Text {
		if canon, ok := i18n.Canonical(lang); !ok || canon != lang {
			fail("text: unsupported language %q", lang)
		}
		for k, v := range m {
			if !known[k] {
				fail("text.%s: unknown key %q (known: %s)", lang, k, strings.Join(TextKeys, ", "))
			}
			if strings.TrimSpace(v) == "" {
				fail("text.%s.%s: empty value", lang, k)
			}
		}
	}
	if err := i18n.ValidateOverrides(b.Messages); err != nil {
		fail("messages: %v", err)
	}
	return errors.Join(errs...)
}

// originOf returns the https origin of raw. A bare origin is required unless
// withPath is set, which allows the path and query a stylesheet URL carries.
// Characters that would let the value break out of a CSP directive are refused
// outright rather than escaped: there is no escaping inside a header value.
func originOf(raw string, withPath bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
		strings.ContainsAny(u.Host, " ;,'\"") {
		return "", fmt.Errorf("%q must be an https URL", raw)
	}
	if !withPath && ((u.Path != "" && u.Path != "/") || u.RawQuery != "") {
		return "", fmt.Errorf("%q must be an origin (scheme and host only)", raw)
	}
	return "https://" + u.Host, nil
}

// Files returns the brand directory's files by name, for serving under
// /static/brand/. The map is shared; callers must not modify it.
func (b *Brand) Files() map[string][]byte { return b.files }

// Host is the host part of URL, for the logo link's accessible label.
func (b *Brand) Host() string {
	u, err := url.Parse(b.URL)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(u.Hostname(), "www.")
}

// TextFor returns the operator text for lang, falling back per key to the
// default language, and leaving out keys the brand does not define.
func (b *Brand) TextFor(lang string) map[string]string {
	out := map[string]string{}
	for _, k := range TextKeys {
		if v, ok := b.Text[lang][k]; ok {
			out[k] = v
		} else if v, ok := b.Text[i18n.DefaultLang][k]; ok {
			out[k] = v
		}
	}
	return out
}

// StyleOrigins are the external origins stylesheets are loaded from.
func (b *Brand) StyleOrigins() []string {
	if b.Fonts.Stylesheet == "" {
		return nil
	}
	o, err := originOf(b.Fonts.Stylesheet, true)
	if err != nil {
		return nil
	}
	return []string{o}
}

// FontOrigins are the external origins font files are loaded from.
func (b *Brand) FontOrigins() []string {
	out := make([]string, 0, len(b.Fonts.FontOrigins))
	for _, raw := range b.Fonts.FontOrigins {
		if o, err := originOf(raw, false); err == nil {
			out = append(out, o)
		}
	}
	return out
}
