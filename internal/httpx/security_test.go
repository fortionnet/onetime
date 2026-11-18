package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func cspFor(t *testing.T, styles, fonts []string) string {
	t.Helper()
	h := SecurityHeaders("https://onetime.example", styles, fonts)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	return w.Header().Get("Content-Security-Policy")
}

func TestCSPCarriesBrandFontOrigins(t *testing.T) {
	csp := cspFor(t, []string{"https://fonts.googleapis.com"}, []string{"https://fonts.gstatic.com"})
	for _, want := range []string{
		"' https://fonts.googleapis.com;", // after the nonce in style-src
		"font-src 'self' https://fonts.gstatic.com;",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
}

func TestCSPWithoutExternalFontsIsSameOrigin(t *testing.T) {
	csp := cspFor(t, nil, nil)
	if !strings.Contains(csp, "font-src 'self';") {
		t.Errorf("CSP %q: font-src should be 'self' only", csp)
	}
	if strings.Contains(csp, "googleapis") || strings.Contains(csp, "gstatic") {
		t.Errorf("CSP %q still allows a font CDN nobody configured", csp)
	}
}
