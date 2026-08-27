package web

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The custom-TTL label is the one string built with printf rather than looked
// up whole, so a stray verb in the catalogue would render as "%!d(MISSING)"
// on the live page and nothing else would notice.
func TestPagesRenderWithoutRawKeysOrFormatVerbs(t *testing.T) {
	mux := newTestHandler(t)

	for _, path := range []string{"/cs/", "/en/", "/cs/api", "/en/api", "/cs/privacy", "/en/privacy"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Errorf("%s: status %d", path, rec.Code)
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, "%!") {
			t.Errorf("%s: printf verb error in rendered output", path)
		}
		// A key the template asks for but the catalogue lacks comes back as
		// its own dotted name, which is otherwise silent in production.
		for _, key := range []string{
			"create.textarea.placeholder", "create.upload.aria",
			"site.description", "api.err.not_found", "create.ttl.custom_label",
		} {
			if strings.Contains(body, key) {
				t.Errorf("%s: unresolved catalog key %q in output", path, key)
			}
		}
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/cs/", nil))
	if !regexp.MustCompile(`Počet dní, \d+ až \d+`).MatchString(rec.Body.String()) {
		t.Error("custom TTL label did not interpolate the configured range")
	}
}
