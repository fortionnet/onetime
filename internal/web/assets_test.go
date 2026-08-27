package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testAssets() *assets {
	return newAssets(fstest.MapFS{
		"js/app.js":    {Data: []byte("export const a = 1;\n")},
		"js/create.js": {Data: []byte("export function init() {}\n")},
		"css/app.css":  {Data: []byte("body{color:red}\n")},
	})
}

func get(a *assets, url string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, url, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestHashedURLIsImmutable(t *testing.T) {
	a := testAssets()
	url := a.URL("css/app.css")
	if !strings.HasPrefix(url, "/static/css/app.") || url == "/static/css/app.css" {
		t.Fatalf("URL did not content-address the file: %q", url)
	}
	w := get(a, url)
	if w.Code != http.StatusOK {
		t.Fatalf("returned %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control = %q, want immutable", cc)
	}
}

// TestUnhashedURLMustRevalidate is the regression guard for a real bug: the
// entry script is content-addressed, but the page modules it pulls in with a
// relative import() are not. Caching those by time let a browser run stale
// JavaScript against fresh markup for the length of the freshness window.
func TestUnhashedURLMustRevalidate(t *testing.T) {
	a := testAssets()
	w := get(a, "/static/js/create.js")
	if w.Code != http.StatusOK {
		t.Fatalf("returned %d", w.Code)
	}
	cc := w.Header().Get("Cache-Control")
	if strings.Contains(cc, "max-age") && !strings.Contains(cc, "max-age=0") {
		t.Fatalf("Cache-Control = %q; a non-addressed module must not be cached by time", cc)
	}
	if cc != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", cc)
	}
}

// TestEveryAssetCarriesAnETag matters because embedded files have a zero
// modification time, so without an explicit validator there is nothing for a
// conditional request to match and "revalidate" would mean a full re-download
// every time.
func TestEveryAssetCarriesAnETag(t *testing.T) {
	a := testAssets()
	for _, url := range []string{"/static/js/create.js", "/static/css/app.css", a.URL("css/app.css")} {
		if tag := get(a, url).Header().Get("ETag"); tag == "" {
			t.Errorf("%s was served without an ETag", url)
		}
	}
}

func TestConditionalRequestGets304(t *testing.T) {
	a := testAssets()
	first := get(a, "/static/js/create.js")
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no ETag to revalidate against")
	}
	second := get(a, "/static/js/create.js", "If-None-Match", tag)
	if second.Code != http.StatusNotModified {
		t.Fatalf("revalidation returned %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Fatalf("304 carried a %d-byte body", second.Body.Len())
	}
}

// TestChangedContentChangesTheETag is what makes the whole scheme work: after a
// deploy the validator must differ, or the browser keeps its stale copy.
func TestChangedContentChangesTheETag(t *testing.T) {
	before := newAssets(fstest.MapFS{"js/create.js": {Data: []byte("old")}})
	after := newAssets(fstest.MapFS{"js/create.js": {Data: []byte("new")}})

	oldTag := get(before, "/static/js/create.js").Header().Get("ETag")
	newTag := get(after, "/static/js/create.js").Header().Get("ETag")
	if oldTag == newTag {
		t.Fatal("the ETag survived a content change; a stale module would never be refetched")
	}
	// And a browser holding the old validator must get the new body, not a 304.
	if w := get(after, "/static/js/create.js", "If-None-Match", oldTag); w.Code != http.StatusOK {
		t.Fatalf("a stale validator returned %d, want 200 with the new content", w.Code)
	}
}

func TestMissingAssetIs404(t *testing.T) {
	if w := get(testAssets(), "/static/js/nope.js"); w.Code != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", w.Code)
	}
}

// TestHumanBytesShowsTheConfiguredLimit guards a mismatch users noticed: the
// file limit is 52428800 bytes because that is a round 50 MiB, and formatting
// it with decimal units advertised "52.4 MB" — a number nobody configured.
func TestHumanBytesShowsTheConfiguredLimit(t *testing.T) {
	for _, tc := range []struct {
		bytes int64
		lang  string
		want  string
	}{
		{52428800, "cs", "50 MB"}, // the upload limit, as users expect to read it
		{52428800, "en", "50 MB"},
		{1048576, "en", "1 MB"},
		{1024, "en", "1 kB"},
		{2516582, "en", "2.4 MB"}, // a decimal still shows where it means something
		{2516582, "cs", "2,4 MB"},
		{512, "en", "512 B"},
		{0, "en", "0 B"},
	} {
		if got := humanBytes(tc.bytes, tc.lang); got != tc.want {
			t.Errorf("humanBytes(%d, %q) = %q, want %q", tc.bytes, tc.lang, got, tc.want)
		}
	}
}

// TestCzechUsesADecimalComma keeps a small but conspicuous detail honest: a
// decimal point in Czech copy reads as an unfinished translation.
func TestCzechUsesADecimalComma(t *testing.T) {
	cs, en := humanBytes(2516582, "cs"), humanBytes(2516582, "en")
	if !strings.Contains(cs, ",") {
		t.Errorf("Czech size %q has no decimal comma", cs)
	}
	if !strings.Contains(en, ".") {
		t.Errorf("English size %q has no decimal point", en)
	}
}
