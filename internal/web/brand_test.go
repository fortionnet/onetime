package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fortionnet/onetime/internal/brand"
)

func fetch(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	body, _ := io.ReadAll(w.Body)
	return w, string(body)
}

// The default brand's logo is served content-addressed from /static/brand/,
// the same way the stylesheet is, and the page links it.
func TestDefaultBrandLogoIsServed(t *testing.T) {
	h := newTestHandler(t)
	_, page := fetch(t, h, "/en/")

	m := regexp.MustCompile(`src="(/static/brand/logo\.[0-9a-f]{10}\.svg)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("page does not reference a hashed brand logo")
	}
	w, _ := fetch(t, h, m[1])
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", m[1], w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable for a hashed URL", cc)
	}
}

// A brand with no logo, no URL and no operator text renders its name and
// nothing of the default brand.
func TestMinimalBrandLeavesNoTraceOfTheDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, brand.ConfigFile), []byte(`{"name": "Example Corp"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := brand.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandlerWith(t, b)

	for _, path := range []string{"/cs/", "/en/", "/en/privacy", "/en/api"} {
		_, page := fetch(t, h, path)
		if strings.Contains(strings.ToLower(page), "fortion") {
			t.Errorf("%s still mentions the default brand", path)
		}
		if path == "/en/" && !strings.Contains(page, `<span class="brand__name">Example Corp</span>`) {
			t.Errorf("%s does not show the brand name in place of a logo", path)
		}
	}
}

func TestDefaultBrandOperatorText(t *testing.T) {
	h := newTestHandler(t)
	_, page := fetch(t, h, "/en/privacy")
	if !strings.Contains(page, "Company ID:") {
		t.Error("privacy page lacks the operator's identifiers")
	}
	_, page = fetch(t, h, "/cs/")
	if !strings.Contains(page, "Provozuje Fortion Networks") {
		t.Error("footer lacks the operator line")
	}
}

// Everything that quotes this service's address quotes the configured one.
func TestBaseURLIsNotHardcoded(t *testing.T) {
	h := newTestHandler(t)
	for _, path := range []string{"/en/api", "/cs/api", "/api/v1/openapi.json", "/llms.txt"} {
		_, body := fetch(t, h, path)
		if strings.Contains(body, "fortion.cloud") || strings.Contains(body, "onetime.invalid") {
			t.Errorf("%s quotes a hardcoded host", path)
		}
		if !strings.Contains(body, "onetime.example") {
			t.Errorf("%s does not quote the configured base URL", path)
		}
	}
}
