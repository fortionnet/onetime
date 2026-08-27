// Package i18n holds the message catalog for the onetime web frontend.
//
// The catalog is a plain map of key to string, one map per language. Keys are
// hierarchical and dot-separated (create.h1, gate.cta, status.expired.title).
// Keys prefixed with "js." are the subset shipped to the browser by JSONFor.
//
// Czech is the default language and the source of truth: every key present in
// the Czech catalog must also exist in every other one, which is enforced by
// the package tests rather than by the type system.
package i18n

import (
	"encoding/json"
	"strings"

	"golang.org/x/text/language"
)

// DefaultLang is the language served when nothing better can be negotiated.
const DefaultLang = "cs"

// jsPrefix marks the catalog keys that are exported to the browser.
const jsPrefix = "js."

var supportedLangs = []string{"cs", "en"}

// matcher is only consulted after an exact base-language scan has failed, so
// its job is limited to salvaging regional or macrolanguage tags.
var matcher = language.NewMatcher([]language.Tag{
	language.Czech,   // index 0 — also the fallback for "no match"
	language.English, // index 1
})

var catalog = map[string]map[string]string{
	"cs": cs,
	"en": en,
}

// Supported returns the language codes the frontend can render, in a stable
// order with DefaultLang first.
func Supported() []string {
	out := make([]string, len(supportedLangs))
	copy(out, supportedLangs)
	return out
}

// IsSupported reports whether lang is one of the languages the frontend can
// render. Comparison is case-insensitive and tolerates surrounding space.
func IsSupported(lang string) bool {
	_, ok := Canonical(lang)
	return ok
}

// Canonical resolves lang to the exact code this package uses for it, or
// reports that it names no supported language.
//
// The returned string is one of this package's own constants rather than a
// reshaped copy of the argument. That distinction matters to callers that put
// the result into a URL: "EN" and "en" both name English, but only one of them
// is a path this service actually serves, and a caller that echoes back what it
// was given is building the URL out of request data instead of out of a fixed
// set.
func Canonical(lang string) (string, bool) {
	lang = normalize(lang)
	for _, l := range supportedLangs {
		if l == lang {
			return l, true
		}
	}
	return "", false
}

// T translates key into lang. An unknown language falls back to DefaultLang,
// an unknown key falls back to the Czech string and finally to the key itself,
// which makes a missing translation loud in the page instead of silent.
func T(lang, key string) string {
	if m, ok := catalog[normalize(lang)]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	if s, ok := catalog[DefaultLang][key]; ok {
		return s
	}
	return key
}

// Translator returns a lookup function bound to lang, suitable for handing to
// html/template as the .T value.
func Translator(lang string) func(string) string {
	l := normalize(lang)
	if !IsSupported(l) {
		l = DefaultLang
	}
	return func(key string) string { return T(l, key) }
}

// Match negotiates the language for a request. An explicit cookie wins, then
// the Accept-Language header (honouring q-values), then DefaultLang.
func Match(acceptLanguage, cookie string) string {
	if IsSupported(cookie) {
		return normalize(cookie)
	}

	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return DefaultLang
	}

	// ParseAcceptLanguage returns tags sorted by descending quality, so the
	// first supported base language is the caller's best supported choice.
	for _, tag := range tags {
		base, conf := tag.Base()
		if conf == language.No {
			continue
		}
		if IsSupported(base.String()) {
			return base.String()
		}
	}

	// Nothing matched outright; let x/text try harder (sr-Latn, zh-Hant, …).
	if _, idx, conf := matcher.Match(tags...); conf > language.No && idx < len(supportedLangs) {
		return supportedLangs[idx]
	}
	return DefaultLang
}

// JSONFor returns a JSON object with every catalog key prefixed by "js.", for
// embedding into the page as <script type="application/json" id="i18n">. Keys
// keep their prefix so that a JS lookup mirrors a Go one.
func JSONFor(lang string) string {
	l := normalize(lang)
	if !IsSupported(l) {
		l = DefaultLang
	}

	out := make(map[string]string, 128)
	for key := range catalog[DefaultLang] {
		if strings.HasPrefix(key, jsPrefix) {
			out[key] = T(l, key)
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func normalize(lang string) string {
	return strings.ToLower(strings.TrimSpace(lang))
}

// ---------------------------------------------------------------------------
// Czech — the source catalog.
// ---------------------------------------------------------------------------

// The catalogues below trip gosec's hardcoded-credential heuristic, which sees
// keys like "create.pass.label" or "gate.pass.placeholder" next to string
// literals and infers a password. They are user-interface copy: the words for
// "password" in two languages, on the labels of the fields a passphrase is
// typed into. No credential is stored anywhere in this package.
//
//nolint:gosec // G101: UI copy about passphrases, not a passphrase
var cs = map[string]string{
	// -- chrome ------------------------------------------------------------
	"site.name":        "onetime",
	"site.title":       "onetime — jednorázové odkazy na hesla a soubory",
	"site.brand_aria":  "Fortion — fortion.cz (otevře se v novém okně)",
	"site.home_aria":   "onetime — úvodní stránka",
	"a11y.skip":        "Přejít na obsah",
	"nav.aria":         "Hlavní navigace",
	"nav.how":          "Jak to funguje",
	"nav.api":          "API",
	"nav.privacy":      "Soukromí",
	"lang.switch_aria": "Přepnout jazyk",
	"lang.cs":          "CS",
	"lang.en":          "EN",
	"footer.privacy":   "Soukromí",
	"footer.nav_aria":  "Odkazy v patičce",
	"footer.operator":  "Provozuje Fortion Networks, s.r.o.",
	"footer.company":   "IČ 26397994 · Smetanovy sady 8, 301 00 Plzeň",
	"footer.api":       "API",
	"footer.tagline":   "Jednorázové odkazy na hesla a soubory.",

	// -- create ------------------------------------------------------------
	"create.title":            "Pošlete heslo, které se po přečtení smaže",
	"create.h1.pre":           "Pošlete heslo, které se po přečtení ",
	"create.h1.mark":          "smaže",
	"create.h1.post":          ".",
	"create.lead":             "Vložte heslo nebo soubor, dostanete odkaz. Kdo ho otevře, uvidí obsah jednou — a nám se smaže. Bez registrace.",
	"create.form_aria":        "Vytvoření jednorázového odkazu",
	"create.tablist_aria":     "Typ obsahu",
	"create.tab.text":         "Text",
	"create.tab.file":         "Soubor",
	"create.textarea.label":   "Obsah, který chcete poslat",
	"create.textarea.hint":    "Vložte heslo, klíč nebo krátkou zprávu.",
	"create.file.drop":        "Přetáhněte soubor sem",
	"create.file.or":          "nebo",
	"create.file.pick":        "Vybrat soubor",
	"create.file.max":         "Maximální velikost",
	"create.file.remove":      "Odebrat soubor",
	"create.file.disabled":    "Posílání souborů je teď vypnuté. Text funguje dál.",
	"create.options.summary":  "Další možnosti",
	"create.ttl.label":        "PLATNOST ODKAZU",
	"create.ttl.d1":           "1 den",
	"create.ttl.d7":           "7 dní",
	"create.ttl.d14":          "14 dní",
	"create.ttl.d30":          "30 dní",
	"create.ttl.custom":       "Jiná…",
	"create.ttl.custom_label": "Počet dní, 1 až 30",
	"create.ttl.back":         "Zpět na výběr",
	"create.pass.label":       "HESLO NAVÍC · VOLITELNÉ",
	"create.pass.placeholder": "Nechte prázdné, pokud ho nechcete",
	"create.pass.show":        "Zobrazit heslo",
	"create.pass.generate":    "Vygenerovat",
	"create.pass.hint":        "Pošlete ho příjemci jinou cestou — SMS nebo telefonem. Bez hesla obsah neotevře.",
	"create.submit":           "Vytvořit odkaz",
	"create.readonly":         "Právě probíhá údržba. Nové odkazy teď nejdou vytvořit.",
	"create.how.kicker":       "JAK TO FUNGUJE",
	"create.how.h2.pre":       "Tři kroky. Žádná ",
	"create.how.h2.mark":      "registrace",
	"create.how.h2.post":      ".",
	"create.how.1.title":      "Vložíte obsah",
	"create.how.1.body":       "Heslo, klíč nebo soubor. Zašifrujeme ho a klíč vložíme do odkazu — ne do databáze.",
	"create.how.2.title":      "Pošlete odkaz",
	"create.how.2.body":       "Chatem, e-mailem, jak chcete. Náhledy v Teams a Slacku obsah nespálí — čekáme na kliknutí od člověka.",
	"create.how.3.title":      "Příjemce ho otevře",
	"create.how.3.body":       "Obsah se ukáže jednou a tím se z našeho serveru smaže. Vy to uvidíte na účtence.",
	"create.result.title":     "Odkaz je připravený",
	"create.result.label":     "Jednorázový odkaz",
	"create.result.copy":      "Kopírovat odkaz",
	"create.result.warn":      "Odkaz vám už znovu neukážeme. Nemáme ho uložený — zkopírujte si ho teď.",

	// -- gate --------------------------------------------------------------
	"gate.title":             "Někdo vám poslal jednorázový obsah",
	"gate.loading":           "Načítám…",
	"gate.h2.text":           "Někdo vám poslal heslo",
	"gate.h2.file":           "Někdo vám poslal soubor",
	"gate.lead":              "Obsah uvidíte jen jednou. Jakmile kliknete, z našeho serveru se smaže.",
	"gate.cta":               "Zobrazit obsah",
	"gate.cta_pass":          "Pokračovat",
	"gate.cta_hint":          "Klikněte, až budete moct obsah rovnou uložit.",
	"gate.chip.text":         "Text",
	"gate.chip.file":         "Soubor",
	"gate.chip.protected":    "Chráněno heslem",
	"gate.why.summary":       "Proč musím klikat?",
	"gate.why.body":          "Teams, Slack, Outlook i WhatsApp si odkazy automaticky otevírají, aby k nim ukázaly náhled. Kdybychom obsah zobrazili rovnou, jejich robot by ho přečetl dřív než vy — a na vás by nezbyl. Proto čekáme na skutečné kliknutí od člověka.",
	"gate.pass.h2":           "Odkaz je chráněný heslem",
	"gate.pass.lead":         "Odesílatel vám ho měl poslat jinou cestou — SMS nebo telefonem.",
	"gate.pass.label":        "Heslo",
	"gate.pass.placeholder":  "Heslo od odesílatele",
	"gate.pass.cta":          "Pokračovat",
	"gate.revealed.aria":     "Odhalený obsah",
	"gate.revealed.copy":     "Kopírovat",
	"gate.revealed.warn":     "Uložte si obsah teď. Až zavřete stránku, je pryč — nikde jinde neexistuje.",
	"gate.revealed.loop":     "Potřebujete poslat něco zpátky?",
	"gate.revealed.loop_cta": "Vytvořit odkaz",
	"gate.file.download":     "Stáhnout soubor",
	"gate.file.downloaded":   "Staženo",
	"gate.file.inapp":        "Pro stažení souboru otevřete stránku v Safari nebo Chrome (⋯ → Otevřít v prohlížeči).",
	"gate.noscript":          "Pro zobrazení obsahu potřebujeme JavaScript.",

	// -- receipt -----------------------------------------------------------
	"receipt.title":                 "Stav odkazu",
	"receipt.kicker":                "STAV ODKAZU",
	"receipt.loading":               "Načítám…",
	"receipt.state.new.title":       "Čeká na přečtení",
	"receipt.state.new.sub":         "Nikdo ho zatím neotevřel.",
	"receipt.state.consumed.title":  "Přečteno",
	"receipt.state.consumed.sub":    "Obsah je smazaný. Hotovo.",
	"receipt.state.burned.title":    "Smazáno vámi",
	"receipt.state.burned.sub":      "Obsah je nenávratně pryč.",
	"receipt.state.destroyed.title": "Obsah byl smazaný",
	"receipt.state.destroyed.sub":   "Někdo opakovaně zadal špatné heslo.",
	"receipt.state.expired.title":   "Vypršelo",
	"receipt.state.expired.sub":     "Nikdo ho nestihl otevřít.",
	"receipt.dl.created":            "Vytvořeno",
	"receipt.dl.expires":            "Vyprší",
	"receipt.dl.content":            "Obsah",
	"receipt.dl.peeked":             "Otevřeno",
	"receipt.dl.consumed":           "Přečteno",
	"receipt.dl.aria":               "Podrobnosti o odkazu",
	"receipt.burn.h3":               "Poslali jste to omylem?",
	"receipt.burn.cta":              "Smazat odkaz teď",
	"receipt.burn.hint":             "Obsah zmizí okamžitě a odkaz už nikdo neotevře.",
	"receipt.burn.confirm.h3":       "Opravdu smazat?",
	"receipt.burn.confirm.body":     "Obsah se smaže hned a nejde vrátit. Kdo odkaz otevře, uvidí, že jste ho zrušili.",
	"receipt.burn.confirm.yes":      "Ano, smazat",
	"receipt.burn.confirm.no":       "Zpět",
	"receipt.bookmark":              "Uložte si tuto stránku do záložek — jinak se k ní nedostanete.",
	"receipt.privacy":               "O příjemci si nic neukládáme — jen čas.",

	// -- status ------------------------------------------------------------
	"status.title":                 "Odkaz není k dispozici",
	"status.cta":                   "Vytvořit vlastní odkaz",
	"status.already_read.title":    "Tenhle odkaz už byl použitý",
	"status.already_read.body":     "Obsah někdo otevřel a tím se smazal. Odkazy tady fungují jen jednou.",
	"status.already_read.why":      "Co když to otevřel někdo jiný?",
	"status.already_read.why_body": "Mohl to udělat robot vašeho e-mailu nebo chatu, který si odkazy sám otevírá — u nás to sice hlídáme, ale u citlivých věcí je bezpečnější předpokládat, že obsah viděl někdo další. Ozvěte se odesílateli, ať heslo pro jistotu změní.",
	"status.expired.title":         "Platnost odkazu vypršela",
	"status.expired.body":          "Nikdo ho nestihl otevřít včas. Požádejte odesílatele o nový.",
	"status.not_found.title":       "Takový odkaz neznáme",
	"status.not_found.body":        "Zkontrolujte, jestli se při kopírování celý přenesl — bývá to tím.",
	"status.burned.title":          "Odesílatel odkaz zrušil",
	"status.burned.body":           "Obsah smazal dřív, než ho někdo otevřel.",
	"status.destroyed.title":       "Obsah byl smazaný",
	"status.destroyed.body":        "Někdo opakovaně zadal špatné heslo, tak jsme obsah pro jistotu zničili.",
	"status.missing_key.title":     "Odkazu chybí konec",
	"status.missing_key.body":      "Zkopíroval se jen kus — část za znakem # je klíč k rozšifrování. Poproste odesílatele, ať vám odkaz pošle znovu.",
	"status.server_error.title":    "Něco se nám rozbilo",
	"status.server_error.body":     "Zkuste to prosím za chvíli znovu. Váš obsah je v pořádku.",
	"status.rate_limited.title":    "Moment, prosím",
	"status.rate_limited.body":     "Z vaší sítě chodí hodně požadavků. Zkuste to za minutu.",
	"status.read_only.title":       "Právě probíhá údržba",
	"status.preview.title":         "Někdo vám poslal jednorázový odkaz",
	"status.preview.body":          "Obsah uvidí jen ten, kdo odkaz otevře jako první. Pak se smaže.",
	"status.read_only.body":        "Nové odkazy teď nejdou vytvořit. Čtení funguje dál.",

	// -- api docs ----------------------------------------------------------
	"api.title":              "API",
	"api.kicker":             "HTTP API",
	"api.h1.pre":             "Jednorázové odkazy ",
	"api.h1.mark":            "z příkazové řádky",
	"api.h1.post":            ".",
	"api.lead":               "Osm endpointů, JSON dovnitř i ven, žádné klíče a žádná registrace. Stejné limity jako ve webu.",
	"api.btn.llms":           "llms.txt",
	"api.btn.openapi":        "OpenAPI",
	"api.toc.title":          "Obsah",
	"api.toc_aria":           "Obsah stránky",
	"api.note.title":         "Poctivá poznámka",
	"api.note.body":          "Šifrování probíhá na serveru. Klíč je součástí odkazu a hned ho zahazujeme — v databázi je obsah bez odkazu nečitelný.",
	"api.s.quickstart.title": "Rychlý start",
	"api.s.quickstart.body":  "Pošlete text, dostanete zpět dva odkazy: jeden pro příjemce a jeden pro sebe. Base URL je onetime.fortion.cloud, všechny endpointy jsou pod /api/v1.",
	"api.s.quickstart.note":  "Odpověď obsahuje klíč jen jednou — v secret_url za znakem #. Nikde ho neukládáme, takže si ho uložte vy.",
	"api.s.create.title":     "Vytvoření odkazu",
	"api.s.create.body":      "Tělo je JSON. Povinný je jen secret; ttl_days je 1 až 30 (výchozí 14) a passphrase je volitelné dodatečné heslo.",
	"api.s.file.title":       "Soubor",
	"api.s.file.body":        "Soubor se posílá jako multipart/form-data. Pole file musí být poslední — server čte metadata dřív, než začne streamovat obsah na disk, a nechce kvůli tomu držet celý soubor v paměti.",
	"api.s.generate.title":   "Generování hesla",
	"api.s.generate.body":    "Server heslo vyrobí sám a rovnou z něj udělá odkaz. Parametr alphabet je letters, alphanumeric nebo symbols, length 8 až 128. S return_value: false se heslo do odpovědi vůbec nedostane.",
	"api.s.reveal.title":     "Přečtení",
	"api.s.reveal.body":      "Nejdřív peek: zjistí typ, velikost a jestli je potřeba heslo, a obsah přitom nespálí. Teprve reveal s confirm: true obsah vydá a smaže. U souboru vrací lístek, se kterým se do pěti minut stáhne obsah z /api/v1/download.",
	"api.s.receipt.title":    "Stav",
	"api.s.receipt.body":     "Účtenka řekne, v jakém stavu odkaz je a kdy se s ním co stalo. O příjemci nevrací nic než časy.",
	"api.s.burn.title":       "Smazání",
	"api.s.burn.body":        "Dokud odkaz nikdo nepřečetl, můžete obsah zničit. Zpátky to nejde.",
	"api.s.errors.title":     "Chyby",
	"api.s.errors.body":      "Chyby jsou application/problem+json podle RFC 9457. Rozhodujte se podle pole code, ne podle textu — ten se mění a je přeložený.",
	"api.s.errors.col_code":  "code",
	"api.s.errors.col_http":  "HTTP",
	"api.s.errors.col_desc":  "Kdy nastane",
	"api.s.limits.title":     "Limity",
	"api.s.limits.body":      "Ve výchozím nastavení text do 1 MB, soubor do 50 MB a platnost 1 až 30 dní; přesné hodnoty ukazuje formulář. Pět špatných pokusů o heslo obsah zničí. Rate limit je na IP a vrací 429 s hlavičkou Retry-After.",
	"api.s.agents.title":     "Pro AI agenty",
	"api.s.agents.body":      "Když má agent předat heslo člověku, doporučujeme POST /api/v1/generate s return_value: false. Heslo vyrobí server, agent dostane jen odkaz — heslo se tedy nikdy nedostane do jeho kontextu, do logu ani do historie konverzace.",
	"api.s.agents.llms":      "Strojově čitelný popis služby je na /llms.txt.",

	// -- privacy -----------------------------------------------------------
	"privacy.title":          "Soukromí",
	"privacy.kicker":         "SOUKROMÍ",
	"privacy.h1":             "Jak to funguje a co si ukládáme",
	"privacy.lead":           "Krátce: obsah držíme zašifrovaný jen do prvního přečtení nebo do vypršení. Klíč k němu nemáme.",
	"privacy.not.title":      "Co si NEUKLÁDÁME",
	"privacy.not.1":          "Obsah v čitelné podobě",
	"privacy.not.2":          "Dešifrovací klíč — ten je jen v odkazu",
	"privacy.not.3":          "IP adresu příjemce",
	"privacy.not.4":          "Analytiku ani trackery",
	"privacy.yes.title":      "Co si ukládáme",
	"privacy.yes.1":          "Zašifrovaná data do přečtení nebo vypršení",
	"privacy.yes.2":          "Čas vytvoření a čas přečtení",
	"privacy.yes.3":          "Volbu jazyka v cookie",
	"privacy.yes.4":          "Provozní logy po dobu 7 dní",
	"privacy.tech.summary":   "Technické detaily",
	"privacy.tech.1":         "Obsah šifrujeme AES-256-GCM. Klíč pro každý odkaz je náhodný a odvozujeme z něj přes HKDF zvlášť klíč pro data a pro metadata.",
	"privacy.tech.2":         "Klíč se objeví jen ve fragmentu odkazu za znakem #. Fragment prohlížeč podle specifikace HTTP nikdy neposílá na server — nedostane se tedy ani do našich logů, ani do logů proxy po cestě.",
	"privacy.tech.3":         "Dodatečné heslo protahujeme přes Argon2id. Po pěti špatných pokusech obsah zničíme.",
	"privacy.tech.4":         "Celý provoz jde přes TLS. Smazání znamená smazání záznamu i zašifrovaného souboru, ne jen příznak v databázi.",
	"privacy.operator.title": "Provozovatel",
	"privacy.operator.body":  "Službu provozuje Fortion Networks, s.r.o.",
	"privacy.operator.addr":  "Smetanovy sady 8, 301 00 Plzeň",
	"privacy.operator.ico":   "IČ: 26397994 · DIČ: CZ26397994",
	"privacy.updated":        "Naposledy upraveno: 27. 8. 2026",

	// -- strings shipped to the browser ------------------------------------
	"js.lang":                      "cs",
	"js.locale":                    "cs-CZ",
	"js.copy":                      "Kopírovat",
	"js.copied":                    "Zkopírováno",
	"js.copy_failed":               "Zkopírujte to podržením prstu na textu.",
	"js.creating":                  "Vytvářím…",
	"js.uploading":                 "Nahrávám",
	"js.upload_cancel":             "Zrušit",
	"js.upload_canceled":           "Nahrávání zrušeno.",
	"js.upload_remaining":          "zbývá ~{t}",
	"js.unit.of":                   "z",
	"js.unit.sec":                  "s",
	"js.unit.min":                  "min",
	"js.days.one":                  "den",
	"js.days.few":                  "dny",
	"js.days.many":                 "dní",
	"js.attempts.one":              "pokus",
	"js.attempts.few":              "pokusy",
	"js.attempts.many":             "pokusů",
	"js.summary.expires":           "Vyprší za {n} {unit}",
	"js.summary.pass":              "s heslem",
	"js.summary.nopass":            "bez hesla",
	"js.expires_on":                "Vyprší {date}",
	"js.kind.text":                 "Text",
	"js.kind.file":                 "Soubor",
	"js.none":                      "—",
	"js.gate.wrong":                "Heslo nesedí.",
	"js.gate.attempts_left":        "Zbývá {n} {unit}. Po vyčerpání se obsah smaže.",
	"js.gate.last_attempt":         "Zbývá poslední pokus. Po něm se obsah smaže.",
	"js.gate.pass_required":        "Zadejte heslo.",
	"js.gate.revealing":            "Zobrazuji…",
	"js.gate.revealed_live":        "Obsah je zobrazený níže. Zkopírujte si ho, znovu se nenačte.",
	"js.gate.downloading":          "Stahuji…",
	"js.gate.download_again":       "Stáhnout znovu",
	"js.receipt.h2":                "Odkaz z {date}",
	"js.receipt.burning":           "Mažu…",
	"js.receipt.burned_live":       "Odkaz je smazaný.",
	"js.leave_warning":             "Odkaz jste si ještě nezkopírovali.",
	"js.err.generic":               "Něco se nepovedlo. Zkuste to prosím znovu.",
	"js.err.network":               "Nepodařilo se spojit se serverem. Zkontrolujte připojení.",
	"js.err.not_found":             "Takový odkaz neznáme.",
	"js.err.already_revealed":      "Obsah už byl přečtený a tím se smazal.",
	"js.err.burned":                "Odesílatel odkaz zrušil.",
	"js.err.destroyed":             "Obsah byl smazaný po opakovaně špatném heslu.",
	"js.err.passphrase_required":   "Odkaz je chráněný heslem.",
	"js.err.bad_passphrase":        "Heslo nesedí.",
	"js.err.too_many_attempts":     "Vyčerpali jste pokusy a obsah je smazaný.",
	"js.err.confirmation_required": "Potvrďte zobrazení obsahu.",
	"js.err.payload_too_large":     "Obsah je moc velký.",
	"js.err.empty":                 "Vložte obsah, který chcete poslat.",
	"js.err.storage_full":          "Došlo nám místo. Zkuste to za chvíli.",
	"js.err.files_disabled":        "Posílání souborů je teď vypnuté.",
	"js.err.read_only":             "Právě probíhá údržba. Nové odkazy teď nejdou vytvořit.",
	"js.err.quota_exceeded":        "Z vaší sítě jde moc odkazů. Zkuste to za chvíli.",
	"js.err.ticket_expired":        "Odkaz na stažení vypršel. Načtěte stránku znovu.",
	"js.err.invalid_ttl":           "Platnost musí být 1 až 30 dní.",
	"js.err.rate_limited":          "Moment — z vaší sítě chodí hodně požadavků. Zkuste to za minutu.",
	"js.err.internal":              "Něco se nám rozbilo. Zkuste to prosím za chvíli znovu.",
}

// ---------------------------------------------------------------------------
// English.
// ---------------------------------------------------------------------------

//nolint:gosec // G101: UI copy about passphrases, not a passphrase; see the note on cs
var en = map[string]string{
	// -- chrome ------------------------------------------------------------
	"site.name":        "onetime",
	"site.title":       "onetime — one-time links for passwords and files",
	"site.brand_aria":  "Fortion — fortion.cz (opens in a new window)",
	"site.home_aria":   "onetime — home page",
	"a11y.skip":        "Skip to content",
	"nav.aria":         "Main navigation",
	"nav.how":          "How it works",
	"nav.api":          "API",
	"nav.privacy":      "Privacy",
	"lang.switch_aria": "Switch language",
	"lang.cs":          "CS",
	"lang.en":          "EN",
	"footer.privacy":   "Privacy",
	"footer.nav_aria":  "Footer links",
	"footer.operator":  "Operated by Fortion Networks, s.r.o.",
	"footer.company":   "Company ID 26397994 · Smetanovy sady 8, 301 00 Plzeň, Czech Republic",
	"footer.api":       "API",
	"footer.tagline":   "One-time links for passwords and files.",

	// -- create ------------------------------------------------------------
	"create.title":            "Send a password that deletes itself once read",
	"create.h1.pre":           "Send a password that deletes itself once it is ",
	"create.h1.mark":          "read",
	"create.h1.post":          ".",
	"create.lead":             "Paste a password or drop a file and get a link. Whoever opens it sees the content once — then it is gone from our server. No sign-up.",
	"create.form_aria":        "Create a one-time link",
	"create.tablist_aria":     "Content type",
	"create.tab.text":         "Text",
	"create.tab.file":         "File",
	"create.textarea.label":   "What you want to send",
	"create.textarea.hint":    "Paste a password, a key or a short message.",
	"create.file.drop":        "Drop a file here",
	"create.file.or":          "or",
	"create.file.pick":        "Choose a file",
	"create.file.max":         "Maximum size",
	"create.file.remove":      "Remove file",
	"create.file.disabled":    "File sending is switched off right now. Text still works.",
	"create.options.summary":  "More options",
	"create.ttl.label":        "LINK VALIDITY",
	"create.ttl.d1":           "1 day",
	"create.ttl.d7":           "7 days",
	"create.ttl.d14":          "14 days",
	"create.ttl.d30":          "30 days",
	"create.ttl.custom":       "Custom…",
	"create.ttl.custom_label": "Number of days, 1 to 30",
	"create.ttl.back":         "Back to presets",
	"create.pass.label":       "EXTRA PASSWORD · OPTIONAL",
	"create.pass.placeholder": "Leave empty if you don't want one",
	"create.pass.show":        "Show password",
	"create.pass.generate":    "Generate",
	"create.pass.hint":        "Send it to the recipient another way — by text message or over the phone. Without it they cannot open the content.",
	"create.submit":           "Create link",
	"create.readonly":         "Maintenance is in progress. New links cannot be created right now.",
	"create.how.kicker":       "HOW IT WORKS",
	"create.how.h2.pre":       "Three steps. No ",
	"create.how.h2.mark":      "sign-up",
	"create.how.h2.post":      ".",
	"create.how.1.title":      "You paste the content",
	"create.how.1.body":       "A password, a key or a file. We encrypt it and put the key in the link — not in the database.",
	"create.how.2.title":      "You send the link",
	"create.how.2.body":       "Chat, e-mail, whatever you use. Link previews in Teams and Slack cannot burn it — we wait for a real human click.",
	"create.how.3.title":      "They open it once",
	"create.how.3.body":       "The content shows up once and is deleted from our server. You see what happened on your receipt.",
	"create.result.title":     "Your link is ready",
	"create.result.label":     "One-time link",
	"create.result.copy":      "Copy link",
	"create.result.warn":      "We will not show you this link again. We do not keep it — copy it now.",

	// -- gate --------------------------------------------------------------
	"gate.title":             "Someone sent you a one-time link",
	"gate.loading":           "Loading…",
	"gate.h2.text":           "Someone sent you a password",
	"gate.h2.file":           "Someone sent you a file",
	"gate.lead":              "You will see the content only once. The moment you click, it is deleted from our server.",
	"gate.cta":               "Show the content",
	"gate.cta_pass":          "Continue",
	"gate.cta_hint":          "Click when you are ready to save the content right away.",
	"gate.chip.text":         "Text",
	"gate.chip.file":         "File",
	"gate.chip.protected":    "Password protected",
	"gate.why.summary":       "Why do I have to click?",
	"gate.why.body":          "Teams, Slack, Outlook and WhatsApp open links on their own to show you a preview. If we revealed the content straight away, their bot would read it before you did — and nothing would be left for you. That is why we wait for a real human click.",
	"gate.pass.h2":           "This link is password protected",
	"gate.pass.lead":         "The sender should have given you the password another way — by text message or over the phone.",
	"gate.pass.label":        "Password",
	"gate.pass.placeholder":  "Password from the sender",
	"gate.pass.cta":          "Continue",
	"gate.revealed.aria":     "Revealed content",
	"gate.revealed.copy":     "Copy",
	"gate.revealed.warn":     "Save the content now. Once you close this page it is gone — it exists nowhere else.",
	"gate.revealed.loop":     "Need to send something back?",
	"gate.revealed.loop_cta": "Create a link",
	"gate.file.download":     "Download the file",
	"gate.file.downloaded":   "Downloaded",
	"gate.file.inapp":        "To download the file, open this page in Safari or Chrome (⋯ → Open in browser).",
	"gate.noscript":          "We need JavaScript to show the content.",

	// -- receipt -----------------------------------------------------------
	"receipt.title":                 "Link status",
	"receipt.kicker":                "LINK STATUS",
	"receipt.loading":               "Loading…",
	"receipt.state.new.title":       "Waiting to be read",
	"receipt.state.new.sub":         "Nobody has opened it yet.",
	"receipt.state.consumed.title":  "Read",
	"receipt.state.consumed.sub":    "The content is deleted. All done.",
	"receipt.state.burned.title":    "Deleted by you",
	"receipt.state.burned.sub":      "The content is gone for good.",
	"receipt.state.destroyed.title": "The content was deleted",
	"receipt.state.destroyed.sub":   "Someone entered the wrong password repeatedly.",
	"receipt.state.expired.title":   "Expired",
	"receipt.state.expired.sub":     "Nobody opened it in time.",
	"receipt.dl.created":            "Created",
	"receipt.dl.expires":            "Expires",
	"receipt.dl.content":            "Content",
	"receipt.dl.peeked":             "Opened",
	"receipt.dl.consumed":           "Read",
	"receipt.dl.aria":               "Link details",
	"receipt.burn.h3":               "Sent it by mistake?",
	"receipt.burn.cta":              "Delete the link now",
	"receipt.burn.hint":             "The content disappears immediately and nobody can open the link.",
	"receipt.burn.confirm.h3":       "Delete it for good?",
	"receipt.burn.confirm.body":     "The content is deleted right away and cannot be brought back. Anyone opening the link will see that you cancelled it.",
	"receipt.burn.confirm.yes":      "Yes, delete",
	"receipt.burn.confirm.no":       "Back",
	"receipt.bookmark":              "Bookmark this page — there is no other way back to it.",
	"receipt.privacy":               "We store nothing about the recipient — only timestamps.",

	// -- status ------------------------------------------------------------
	"status.title":                 "Link unavailable",
	"status.cta":                   "Create your own link",
	"status.already_read.title":    "This link has already been used",
	"status.already_read.body":     "Someone opened the content and that deleted it. Links here work exactly once.",
	"status.already_read.why":      "What if it wasn't me who opened it?",
	"status.already_read.why_body": "It may have been a bot from your e-mail or chat that opens links on its own — we do guard against that, but with sensitive material it is safer to assume somebody else saw the content. Get in touch with the sender and have the password changed.",
	"status.expired.title":         "This link has expired",
	"status.expired.body":          "Nobody opened it in time. Ask the sender for a new one.",
	"status.not_found.title":       "We don't know this link",
	"status.not_found.body":        "Check whether the whole link came across when it was copied — that is usually the cause.",
	"status.burned.title":          "The sender cancelled this link",
	"status.burned.body":           "They deleted the content before anyone opened it.",
	"status.destroyed.title":       "The content was deleted",
	"status.destroyed.body":        "Someone entered the wrong password repeatedly, so we destroyed the content to be safe.",
	"status.missing_key.title":     "The end of the link is missing",
	"status.missing_key.body":      "Only part of it came across — everything after the # is the decryption key. Ask the sender to send you the link again.",
	"status.server_error.title":    "Something broke on our side",
	"status.server_error.body":     "Please try again in a moment. Your content is fine.",
	"status.rate_limited.title":    "One moment, please",
	"status.rate_limited.body":     "There are a lot of requests coming from your network. Try again in a minute.",
	"status.read_only.title":       "Maintenance in progress",
	"status.preview.title":         "Someone sent you a one-time link",
	"status.preview.body":          "Only the first person to open it sees the content. Then it is deleted.",
	"status.read_only.body":        "New links cannot be created right now. Reading still works.",

	// -- api docs ----------------------------------------------------------
	"api.title":              "API",
	"api.kicker":             "HTTP API",
	"api.h1.pre":             "One-time links ",
	"api.h1.mark":            "from the command line",
	"api.h1.post":            ".",
	"api.lead":               "Eight endpoints, JSON in and out, no API keys and no sign-up. Same limits as the web app.",
	"api.btn.llms":           "llms.txt",
	"api.btn.openapi":        "OpenAPI",
	"api.toc.title":          "Contents",
	"api.toc_aria":           "Page contents",
	"api.note.title":         "An honest note",
	"api.note.body":          "Encryption happens on the server. The key is part of the link and we throw it away immediately — without the link, the content in our database is unreadable.",
	"api.s.quickstart.title": "Quick start",
	"api.s.quickstart.body":  "Send some text, get two links back: one for the recipient and one for yourself. The base URL is onetime.fortion.cloud and every endpoint lives under /api/v1.",
	"api.s.quickstart.note":  "The response contains the key exactly once — in secret_url, after the #. We never store it, so you have to.",
	"api.s.create.title":     "Creating a link",
	"api.s.create.body":      "The body is JSON. Only secret is required; ttl_days is 1 to 30 (default 14) and passphrase is an optional extra password.",
	"api.s.file.title":       "File upload",
	"api.s.file.body":        "Files go up as multipart/form-data. The file field must come last — the server reads the metadata before it starts streaming the body to disk, so that it never has to hold the whole file in memory.",
	"api.s.generate.title":   "Password generation",
	"api.s.generate.body":    "The server makes the password itself and turns it straight into a link. alphabet is letters, alphanumeric or symbols, length is 8 to 128. With return_value: false the password never appears in the response at all.",
	"api.s.reveal.title":     "Reading",
	"api.s.reveal.body":      "Start with peek: it reports the kind, the size and whether a password is needed, without burning anything. Only reveal with confirm: true hands out the content and deletes it. For files it returns a ticket good for five minutes against /api/v1/download.",
	"api.s.receipt.title":    "Status",
	"api.s.receipt.body":     "The receipt tells you what state the link is in and when things happened to it. It returns nothing about the recipient beyond timestamps.",
	"api.s.burn.title":       "Deleting",
	"api.s.burn.body":        "As long as nobody has read the link, you can destroy the content. There is no undo.",
	"api.s.errors.title":     "Errors",
	"api.s.errors.body":      "Errors are application/problem+json per RFC 9457. Branch on the code field, not on the text — the text changes and is translated.",
	"api.s.errors.col_code":  "code",
	"api.s.errors.col_http":  "HTTP",
	"api.s.errors.col_desc":  "When it happens",
	"api.s.limits.title":     "Limits",
	"api.s.limits.body":      "By default text up to 1 MB, files up to 50 MB and validity between 1 and 30 days; the form shows the exact figures. Five wrong password attempts destroy the content. Rate limiting is per IP and answers 429 with a Retry-After header.",
	"api.s.agents.title":     "For AI agents",
	"api.s.agents.body":      "When an agent has to hand a password to a human, use POST /api/v1/generate with return_value: false. The server makes the password and the agent only ever sees a link — so the password never enters the agent's context, its logs or the conversation history.",
	"api.s.agents.llms":      "A machine-readable description of the service lives at /llms.txt.",

	// -- privacy -----------------------------------------------------------
	"privacy.title":          "Privacy",
	"privacy.kicker":         "PRIVACY",
	"privacy.h1":             "How it works and what we store",
	"privacy.lead":           "In short: we hold the content encrypted only until the first read or until it expires. We do not have the key to it.",
	"privacy.not.title":      "What we DON'T store",
	"privacy.not.1":          "The content in readable form",
	"privacy.not.2":          "The decryption key — it only lives in the link",
	"privacy.not.3":          "The recipient's IP address",
	"privacy.not.4":          "Analytics or trackers",
	"privacy.yes.title":      "What we do store",
	"privacy.yes.1":          "Encrypted data until it is read or expires",
	"privacy.yes.2":          "The time of creation and of reading",
	"privacy.yes.3":          "Your language choice, in a cookie",
	"privacy.yes.4":          "Operational logs for 7 days",
	"privacy.tech.summary":   "Technical details",
	"privacy.tech.1":         "Content is encrypted with AES-256-GCM. Each link gets a random key, from which HKDF derives separate keys for the payload and for the metadata.",
	"privacy.tech.2":         "The key appears only in the link fragment, after the #. Per the HTTP specification a browser never sends the fragment to a server — so it reaches neither our logs nor any proxy along the way.",
	"privacy.tech.3":         "An extra password is stretched with Argon2id. After five wrong attempts we destroy the content.",
	"privacy.tech.4":         "All traffic runs over TLS. Deleting means deleting the record and the encrypted file, not just flipping a flag in a database.",
	"privacy.operator.title": "Operator",
	"privacy.operator.body":  "The service is operated by Fortion Networks, s.r.o., registered in the Czech Republic.",
	"privacy.operator.addr":  "Smetanovy sady 8, 301 00 Plzeň, Czech Republic",
	"privacy.operator.ico":   "Company ID: 26397994 · VAT ID: CZ26397994",
	"privacy.updated":        "Last updated: 27 Aug 2026",

	// -- strings shipped to the browser ------------------------------------
	"js.lang":                      "en",
	"js.locale":                    "en-GB",
	"js.copy":                      "Copy",
	"js.copied":                    "Copied",
	"js.copy_failed":               "Copy it by pressing and holding on the text.",
	"js.creating":                  "Creating…",
	"js.uploading":                 "Uploading",
	"js.upload_cancel":             "Cancel",
	"js.upload_canceled":           "Upload cancelled.",
	"js.upload_remaining":          "~{t} left",
	"js.unit.of":                   "of",
	"js.unit.sec":                  "s",
	"js.unit.min":                  "min",
	"js.days.one":                  "day",
	"js.days.few":                  "days",
	"js.days.many":                 "days",
	"js.attempts.one":              "attempt",
	"js.attempts.few":              "attempts",
	"js.attempts.many":             "attempts",
	"js.summary.expires":           "Expires in {n} {unit}",
	"js.summary.pass":              "with a password",
	"js.summary.nopass":            "no password",
	"js.expires_on":                "Expires {date}",
	"js.kind.text":                 "Text",
	"js.kind.file":                 "File",
	"js.none":                      "—",
	"js.gate.wrong":                "That password is wrong.",
	"js.gate.attempts_left":        "{n} {unit} left. When they run out the content is deleted.",
	"js.gate.last_attempt":         "One attempt left. After that the content is deleted.",
	"js.gate.pass_required":        "Enter the password.",
	"js.gate.revealing":            "Revealing…",
	"js.gate.revealed_live":        "The content is shown below. Copy it, it will not load again.",
	"js.gate.downloading":          "Downloading…",
	"js.gate.download_again":       "Download again",
	"js.receipt.h2":                "Link from {date}",
	"js.receipt.burning":           "Deleting…",
	"js.receipt.burned_live":       "The link is deleted.",
	"js.leave_warning":             "You have not copied the link yet.",
	"js.err.generic":               "Something went wrong. Please try again.",
	"js.err.network":               "We could not reach the server. Check your connection.",
	"js.err.not_found":             "We don't know this link.",
	"js.err.already_revealed":      "The content has already been read and is deleted.",
	"js.err.burned":                "The sender cancelled this link.",
	"js.err.destroyed":             "The content was deleted after repeated wrong passwords.",
	"js.err.passphrase_required":   "This link is password protected.",
	"js.err.bad_passphrase":        "That password is wrong.",
	"js.err.too_many_attempts":     "You have used up your attempts and the content is deleted.",
	"js.err.confirmation_required": "Confirm that you want to see the content.",
	"js.err.payload_too_large":     "The content is too large.",
	"js.err.empty":                 "Add the content you want to send.",
	"js.err.storage_full":          "We have run out of space. Try again shortly.",
	"js.err.files_disabled":        "File sending is switched off right now.",
	"js.err.read_only":             "Maintenance is in progress. New links cannot be created right now.",
	"js.err.quota_exceeded":        "Too many links from your network. Try again shortly.",
	"js.err.ticket_expired":        "The download link expired. Reload the page.",
	"js.err.invalid_ttl":           "Validity has to be between 1 and 30 days.",
	"js.err.rate_limited":          "One moment — a lot of requests are coming from your network. Try again in a minute.",
	"js.err.internal":              "Something broke on our side. Please try again in a moment.",
}
