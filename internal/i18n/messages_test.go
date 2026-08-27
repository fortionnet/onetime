package i18n

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A missing translation is invisible in production — T falls back to Czech and
// the page still renders — so the only place it can be caught is here.
func TestCatalogsHaveIdenticalKeys(t *testing.T) {
	base := catalog[DefaultLang]

	for lang, m := range catalog {
		if lang == DefaultLang {
			continue
		}

		var missing, extra []string
		for k := range base {
			if _, ok := m[k]; !ok {
				missing = append(missing, k)
			}
		}
		for k := range m {
			if _, ok := base[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)

		if len(missing) > 0 {
			t.Errorf("catalog %q is missing %d keys: %v", lang, len(missing), missing)
		}
		if len(extra) > 0 {
			t.Errorf("catalog %q has %d keys absent from %q: %v", lang, len(extra), DefaultLang, extra)
		}
	}
}

func TestNoEmptyOrUntrimmedValues(t *testing.T) {
	for lang, m := range catalog {
		for k, v := range m {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s/%s: empty value", lang, k)
			}
			// Deliberate exception: sentence fragments that are concatenated
			// around a highlighted word in the template need their spacing.
			if strings.HasSuffix(k, ".pre") {
				continue
			}
			if v != strings.TrimSpace(v) {
				t.Errorf("%s/%s: value has leading or trailing whitespace: %q", lang, k, v)
			}
		}
	}
}

// Every catalog must be listed in Supported and vice versa, otherwise the
// language switcher offers something T cannot render.
func TestSupportedMatchesCatalog(t *testing.T) {
	got := Supported()
	if len(got) != len(catalog) {
		t.Fatalf("Supported() = %v, catalog has %d languages", got, len(catalog))
	}
	if got[0] != DefaultLang {
		t.Errorf("Supported()[0] = %q, want DefaultLang %q", got[0], DefaultLang)
	}
	for _, l := range got {
		if _, ok := catalog[l]; !ok {
			t.Errorf("Supported() lists %q which has no catalog", l)
		}
		if !IsSupported(l) {
			t.Errorf("IsSupported(%q) = false", l)
		}
	}

	// The returned slice must not alias package state.
	got[0] = "xx"
	if Supported()[0] != DefaultLang {
		t.Error("Supported() returns a slice that aliases package state")
	}
}

func TestIsSupported(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"cs", true},
		{"en", true},
		{"CS", true},
		{" en ", true},
		{"cs-CZ", false}, // a full tag is not a catalog key
		{"de", false},
		{"", false},
	} {
		if got := IsSupported(tc.in); got != tc.want {
			t.Errorf("IsSupported(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestTranslate(t *testing.T) {
	if got := T("cs", "create.submit"); got != "Vytvořit odkaz" {
		t.Errorf("T(cs, create.submit) = %q", got)
	}
	if got := T("en", "create.submit"); got != "Create link" {
		t.Errorf("T(en, create.submit) = %q", got)
	}
	// Unknown language falls back to Czech rather than to the key.
	if got := T("de", "create.submit"); got != T(DefaultLang, "create.submit") {
		t.Errorf("T(de, ...) = %q, want the Czech string", got)
	}
	// An unknown key surfaces as the key itself so it is visible in the page.
	if got := T("cs", "no.such.key"); got != "no.such.key" {
		t.Errorf("T(cs, no.such.key) = %q, want the key back", got)
	}
}

func TestTranslator(t *testing.T) {
	en := Translator("en")
	if got := en("nav.how"); got != "How it works" {
		t.Errorf("Translator(en)(nav.how) = %q", got)
	}
	// An unsupported language still yields a working translator.
	if got := Translator("de")("nav.how"); got != T(DefaultLang, "nav.how") {
		t.Errorf("Translator(de)(nav.how) = %q, want the Czech string", got)
	}
	if got := Translator("EN")("nav.how"); got != "How it works" {
		t.Errorf("Translator(EN) did not normalise the language")
	}
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		cookie string
		want   string
	}{
		{"cookie wins over header", "en-US,en;q=0.9", "cs", "cs"},
		{"cookie wins the other way", "cs-CZ,cs;q=0.9", "en", "en"},
		{"unsupported cookie is ignored", "en-GB", "de", "en"},
		{"czech with region", "cs-CZ,cs;q=0.9", "", "cs"},
		{"english with region", "en-US,en;q=0.9", "", "en"},
		{"q-values decide", "de;q=0.9,en;q=0.8,cs;q=0.7", "", "en"},
		{"lower q still wins if higher is unsupported", "fr,cs;q=0.5", "", "cs"},
		{"unsupported language falls back to default", "de", "", "cs"},
		{"empty header falls back to default", "", "", "cs"},
		{"garbage header falls back to default", "!!!", "", "cs"},
		{"wildcard falls back to default", "*", "", "cs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.accept, tc.cookie); got != tc.want {
				t.Errorf("Match(%q, %q) = %q, want %q", tc.accept, tc.cookie, got, tc.want)
			}
		})
	}
}

// Whatever Match returns must be renderable, for every input.
func TestMatchAlwaysReturnsSupported(t *testing.T) {
	for _, accept := range []string{"", "*", "xx-YY", "de-AT,de;q=0.9", "zh-Hant,ja;q=0.5", "en", "cs"} {
		for _, cookie := range []string{"", "de", "cs", "en", "  EN "} {
			if got := Match(accept, cookie); !IsSupported(got) {
				t.Errorf("Match(%q, %q) = %q which is not supported", accept, cookie, got)
			}
		}
	}
}

func TestJSONFor(t *testing.T) {
	for _, lang := range append(Supported(), "de") {
		raw := JSONFor(lang)

		var got map[string]string
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("JSONFor(%q) is not valid JSON: %v", lang, err)
		}
		if len(got) == 0 {
			t.Fatalf("JSONFor(%q) is empty", lang)
		}

		for k := range got {
			if !strings.HasPrefix(k, jsPrefix) {
				t.Errorf("JSONFor(%q) leaked non-js key %q", lang, k)
			}
		}

		// Every js.* key in the catalog has to be present, otherwise a lookup
		// in the browser silently renders the raw key.
		for k := range catalog[DefaultLang] {
			if strings.HasPrefix(k, jsPrefix) {
				if _, ok := got[k]; !ok {
					t.Errorf("JSONFor(%q) is missing %q", lang, k)
				}
			}
		}
	}

	// The payload is inlined into <script type="application/json">, where an
	// unescaped </script> would end the element early.
	for _, lang := range Supported() {
		if strings.Contains(strings.ToLower(JSONFor(lang)), "</script") {
			t.Errorf("JSONFor(%q) contains a script end tag", lang)
		}
	}

	var cs, en map[string]string
	if err := json.Unmarshal([]byte(JSONFor("cs")), &cs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(JSONFor("en")), &en); err != nil {
		t.Fatal(err)
	}
	if cs["js.lang"] != "cs" || en["js.lang"] != "en" {
		t.Errorf("js.lang not language specific: cs=%q en=%q", cs["js.lang"], en["js.lang"])
	}
	if cs["js.copied"] == en["js.copied"] {
		t.Errorf("js.copied is identical in both languages: %q", cs["js.copied"])
	}
}

// JSONFor output is embedded in a cached, hashed page; identical input must
// produce identical bytes or the cache key stops meaning anything.
func TestJSONForIsDeterministic(t *testing.T) {
	first := JSONFor("cs")
	for i := 0; i < 20; i++ {
		if got := JSONFor("cs"); got != first {
			t.Fatalf("JSONFor is not deterministic:\n%s\n%s", first, got)
		}
	}
}

// The templates reference these keys directly; a rename would otherwise only
// show up as literal dotted text on the page.
func TestKeysUsedByTemplatesExist(t *testing.T) {
	required := []string{
		"a11y.skip", "nav.how", "nav.api", "nav.privacy",
		"create.h1.pre", "create.h1.mark", "create.h1.post", "create.submit",
		"create.result.title", "create.result.warn",
		"gate.h2.text", "gate.h2.file", "gate.cta", "gate.why.body", "gate.noscript",
		"receipt.kicker", "receipt.burn.cta", "receipt.burn.confirm.yes",
		"api.s.agents.body", "privacy.not.title", "privacy.yes.title",
		"js.copied", "js.err.generic", "js.locale",
	}
	for _, variant := range []string{
		"already_read", "expired", "not_found", "burned", "destroyed",
		"missing_key", "server_error", "rate_limited", "read_only",
	} {
		required = append(required, "status."+variant+".title", "status."+variant+".body")
	}
	for _, state := range []string{"new", "consumed", "burned", "destroyed", "expired"} {
		required = append(required, "receipt.state."+state+".title", "receipt.state."+state+".sub")
	}

	for _, key := range required {
		for _, lang := range Supported() {
			if T(lang, key) == key {
				t.Errorf("catalog %q has no entry for %q", lang, key)
			}
		}
	}
}

// A key renamed in the catalog but not in a template renders as literal dotted
// text on the page, which no compiler and no other test would catch. This walks
// the templates and checks every key they ask for.
func TestTemplateKeysExist(t *testing.T) {
	const dir = "../../web/templates"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("templates not present: %v", err)
	}

	// Matches {{call .T "key"}} and {{call $.T "key"}}, the only two forms the
	// templates use. Keys built with printf are dynamic and are covered by
	// TestKeysUsedByTemplatesExist instead.
	re := regexp.MustCompile(`call \$?\.T "([^"]+)"`)

	seen := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".gohtml") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, m := range re.FindAllSubmatch(src, -1) {
			key := string(m[1])
			seen++
			for _, lang := range Supported() {
				if T(lang, key) == key {
					t.Errorf("%s asks for %q, which catalog %q does not define", e.Name(), key, lang)
				}
			}
		}
	}

	if seen == 0 {
		t.Error("no translation calls found in templates; the pattern is probably stale")
	} else {
		t.Logf("checked %d translation calls across the templates", seen)
	}
}

// The browser side needs a stronger guard than the templates do, because the
// page ships only a subset of the catalog: JSONFor exports the "js." keys and
// nothing else. A module that asks for any other key gets the raw key echoed
// back onto the screen — which is exactly how create.js came to render the
// literal text "create.result.chip.nopass".
//
// The old version of this test could not see that, because its pattern only
// matched keys that already began with "js.". This one collects every key any
// t(...) call mentions and asserts it is in the shipped payload, so the rule
// "if JS asks for it, it lives under js." is checked rather than assumed.
func TestJSKeysAreExported(t *testing.T) {
	const dir = "../../web/static/js"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("scripts not present: %v", err)
	}

	// What the browser actually receives, per language.
	exported := map[string]map[string]bool{}
	for _, lang := range Supported() {
		var m map[string]string
		if err := json.Unmarshal([]byte(JSONFor(lang)), &m); err != nil {
			t.Fatalf("JSONFor(%q): %v", lang, err)
		}
		set := make(map[string]bool, len(m))
		for k := range m {
			set[k] = true
		}
		exported[lang] = set
	}

	var (
		// A dotted, lowercase-initial literal is a catalog key. Anchoring the
		// first character rules out the fragments of a built key such as
		// t(base + '.one'), whose family is checked via plural() below.
		keyLit  = regexp.MustCompile(`'([a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+)'`)
		plurals = regexp.MustCompile(`\bplural\([^,]+, '([a-z][a-zA-Z0-9_.]+)'\)`)
	)

	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}

		var keys []string

		// plural() takes a family name and appends the CLDR category, so the
		// bare base is never a key on its own.
		bases := map[string]bool{}
		for _, m := range plurals.FindAllSubmatch(src, -1) {
			base := string(m[1])
			bases[base] = true
			for _, form := range []string{".one", ".few", ".many"} {
				keys = append(keys, base+form)
			}
		}

		// Every literal inside a t(...) call, which covers the ternary form
		// t(cond ? 'js.a' : 'js.b') that a single-key pattern would miss.
		for _, arg := range jsCallArgs(src) {
			for _, m := range keyLit.FindAllStringSubmatch(arg, -1) {
				if bases[m[1]] {
					continue // a plural family nested in the same argument list
				}
				keys = append(keys, m[1])
			}
		}

		for _, key := range keys {
			checked++
			for _, lang := range Supported() {
				if !exported[lang][key] {
					t.Errorf("%s asks for %q, which JSONFor(%q) does not ship; "+
						"keys used from JS must live under the %q prefix", e.Name(), key, lang, jsPrefix)
				}
			}
		}
	}

	if checked == 0 {
		t.Error("no js translation keys found; the pattern is probably stale")
	} else {
		t.Logf("checked %d js translation keys across the modules", checked)
	}
}

// jsCallArgs returns the argument text of every t(...) call in src. Quotes and
// nested parentheses are tracked so that the argument list of a call such as
// t('js.expires_on', { date: formatDate(x) }) is returned whole.
//
// Keys assembled at runtime — api.js builds 'js.err.' + code — cannot be seen
// statically. That one site echoes the error detail when the lookup misses, so
// it degrades to a readable message rather than to a raw key.
func jsCallArgs(src []byte) []string {
	call := regexp.MustCompile(`\bt\(`)

	var out []string
	for _, loc := range call.FindAllIndex(src, -1) {
		start := loc[1]
		depth := 1
		var quote byte

		i := start
		for ; i < len(src); i++ {
			c := src[i]
			if quote != 0 {
				if c == '\\' {
					i++
					continue
				}
				if c == quote {
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"', '`':
				quote = c
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth == 0 {
			out = append(out, string(src[start:i]))
		}
	}
	return out
}

// Placeholders are substituted in JS by literal string replacement, so the
// token has to survive translation.
func TestPlaceholdersSurviveTranslation(t *testing.T) {
	want := map[string][]string{
		"js.summary.expires":    {"{n}", "{unit}"},
		"js.expires_on":         {"{date}"},
		"js.receipt.h2":         {"{date}"},
		"js.gate.attempts_left": {"{n}", "{unit}"},
		"js.upload_remaining":   {"{t}"},
	}
	for key, tokens := range want {
		for _, lang := range Supported() {
			v := T(lang, key)
			for _, tok := range tokens {
				if !strings.Contains(v, tok) {
					t.Errorf("%s/%s = %q, missing placeholder %s", lang, key, v, tok)
				}
			}
		}
	}
}
