#!/usr/bin/env bash
#
# Run the commands documented in docs/llms.txt against a live instance.
#
# This exists because the usage text is a contract with AI agents and shell
# users, and a contract nobody executes drifts. If the API changes and the
# documentation does not, this fails.
#
# Usage: scripts/doctest.sh [base-url]
#        BASE=http://localhost:8080 scripts/doctest.sh

set -euo pipefail

BASE="${1:-${BASE:-http://localhost:8080}}"
PASS=0
FAIL=0
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n'   "$1"; FAIL=$((FAIL + 1)); }
head() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# expect_status <expected> <description> <curl args...>
expect_status() {
  local want="$1" what="$2"; shift 2
  local got
  got="$(curl -sS -o /dev/null -w '%{http_code}' "$@")"
  if [ "$got" = "$want" ]; then ok "$what (HTTP $got)"; else bad "$what: HTTP $got, want $want"; fi
}

json() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

head "Service is up"
expect_status 200 "liveness"  "$BASE/healthz"
expect_status 200 "readiness" "$BASE/readyz"

head "llms.txt is served and reflects the running configuration"
LLMS="$(curl -fsS "$BASE/llms.txt")"
grep -q "SAFETY RULES FOR AI AGENTS" <<<"$LLMS" && ok "usage text carries the agent safety rules" \
  || bad "usage text is missing the agent safety rules"
grep -q "$BASE" <<<"$LLMS" && ok "usage text quotes this instance's base URL" \
  || bad "usage text does not quote this instance's base URL"
# A bare curl against the root should get the usage text, not HTML.
curl -fsS "$BASE/" | grep -q "SAFETY RULES" && ok "a bare curl of the root gets the usage text" \
  || bad "a bare curl of the root did not get the usage text"

head "Pattern 1: the server generates a password and the caller never sees it"
LINK="$(curl -fsS -X POST "$BASE/api/v1/generate" -H 'Accept: text/plain' -d length=24 -d ttl=14d)"
[ "$(wc -l <<<"$LINK")" -eq 1 ] && ok "the response is a single line" || bad "the response spans several lines"
grep -q '#' <<<"$LINK" && ok "the link carries a key in its fragment" || bad "the link has no fragment"
KEY="${LINK##*#}"

head "Pattern 7: peek describes the secret without consuming it"
PEEK="$(printf '{"key":"%s"}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/peek")"
[ "$(json '["state"]' <<<"$PEEK")" = "new" ] && ok "peek reports the secret as unread" || bad "peek reports: $PEEK"

head "A reveal without confirmation is refused and consumes nothing"
expect_status 400 "reveal without confirm is refused" \
  -X POST -H 'Content-Type: application/json' --data-binary "$(printf '{"key":"%s"}' "$KEY")" "$BASE/api/v1/reveal"
printf '{"key":"%s"}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/peek" >/dev/null \
  && ok "the secret survived the refused reveal" || bad "the refused reveal consumed the secret"

head "Link preview bots cannot consume a secret"
for H in "Sec-Purpose: prefetch" "Purpose: prefetch" "X-Moz: prefetch" "X-Purpose: preview"; do
  expect_status 204 "declared prefetch (${H%%:*}) is answered without touching the record" \
    -X POST -H 'Content-Type: application/json' -H "$H" \
    --data-binary "$(printf '{"key":"%s","confirm":true}' "$KEY")" "$BASE/api/v1/reveal"
done
expect_status 403 "a browser navigating straight to reveal is refused" \
  -X POST -H 'Content-Type: application/json' \
  -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Dest: document' \
  --data-binary "$(printf '{"key":"%s","confirm":true}' "$KEY")" "$BASE/api/v1/reveal"
printf '{"key":"%s"}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/peek" >/dev/null \
  && ok "the secret survived every prefetch attempt" || bad "a prefetch attempt consumed the secret"

head "Pattern 5: a confirmed reveal returns the value and destroys it"
VALUE="$(printf '{"key":"%s","confirm":true}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/reveal" | json '["value"]')"
[ "${#VALUE}" -eq 24 ] && ok "the generated password is 24 characters" || bad "the password is ${#VALUE} characters"
expect_status 410 "a second read is refused" \
  -X POST -H 'Content-Type: application/json' \
  --data-binary "$(printf '{"key":"%s","confirm":true}' "$KEY")" "$BASE/api/v1/reveal"

head "Pattern 2: a value piped in on stdin never touches argv"
LINK="$(printf %s 'piped-from-stdin' | curl -fsS --data-binary @- \
  -H 'Content-Type: text/plain' -H 'X-Onetime-TTL: 14d' -H 'Accept: text/plain' "$BASE/api/v1/secret")"
KEY="${LINK##*#}"
GOT="$(printf '{"key":"%s","confirm":true}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/reveal" | json '["value"]')"
[ "$GOT" = "piped-from-stdin" ] && ok "the piped value round-tripped" || bad "round-tripped as '$GOT'"

head "Pattern 3: a file streams up and back down intact"
dd if=/dev/urandom of="$WORKDIR/payload.bin" bs=1048576 count=4 2>/dev/null
BEFORE="$(shasum -a 256 "$WORKDIR/payload.bin" | cut -d' ' -f1)"
LINK="$(curl -fsS -T "$WORKDIR/payload.bin" -H 'Accept: text/plain' \
  "$BASE/api/v1/secret/file?filename=payload.bin&ttl=7d")"
KEY="${LINK##*#}"
REVEAL="$(printf '{"key":"%s","confirm":true}' "$KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/reveal")"
[ "$(json '["filename"]' <<<"$REVEAL")" = "payload.bin" ] && ok "the filename survived encryption" || bad "filename: $REVEAL"
TICKET="$(json '["download_ticket"]' <<<"$REVEAL")"
curl -fsS -H "X-Onetime-Ticket: $TICKET" -o "$WORKDIR/out.bin" "$BASE/api/v1/download"
AFTER="$(shasum -a 256 "$WORKDIR/out.bin" | cut -d' ' -f1)"
[ "$BEFORE" = "$AFTER" ] && ok "the 4 MB file round-tripped byte for byte" || bad "checksum changed: $BEFORE -> $AFTER"

head "Pattern 6: the receipt reports and cancels, but cannot read"
RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' \
  --data-binary '{"secret":"sent-by-mistake"}' "$BASE/api/v1/secret")"
SEC_KEY="$(json '["secret_url"]' <<<"$RESP")"; SEC_KEY="${SEC_KEY##*#}"
REC_KEY="$(json '["receipt_url"]' <<<"$RESP")"; REC_KEY="${REC_KEY##*#}"
STATE="$(printf '{"key":"%s"}' "$REC_KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/receipt" | json '["state"]')"
[ "$STATE" = "new" ] && ok "the receipt reports the secret as unread" || bad "receipt state is '$STATE'"
expect_status 404 "the receipt key cannot be used to read the secret" \
  -X POST -H 'Content-Type: application/json' \
  --data-binary "$(printf '{"key":"%s","confirm":true}' "$REC_KEY")" "$BASE/api/v1/reveal"
STATE="$(printf '{"key":"%s","confirm":true}' "$REC_KEY" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/receipt/burn" | json '["state"]')"
[ "$STATE" = "burned" ] && ok "the sender cancelled the secret" || bad "burn left state '$STATE'"
expect_status 410 "the cancelled secret can no longer be read" \
  -X POST -H 'Content-Type: application/json' \
  --data-binary "$(printf '{"key":"%s","confirm":true}' "$SEC_KEY")" "$BASE/api/v1/reveal"

head "A passphrase adds a second factor without weakening the first"
RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' \
  --data-binary '{"secret":"protected","passphrase":"correct horse","ttl_days":3}' "$BASE/api/v1/secret")"
KEY="$(json '["secret_url"]' <<<"$RESP")"; KEY="${KEY##*#}"
expect_status 401 "a missing passphrase is reported, not guessed at" \
  -X POST -H 'Content-Type: application/json' \
  --data-binary "$(printf '{"key":"%s","confirm":true}' "$KEY")" "$BASE/api/v1/reveal"
expect_status 403 "a wrong passphrase is refused" \
  -X POST -H 'Content-Type: application/json' \
  --data-binary "$(printf '{"key":"%s","confirm":true,"passphrase":"nope"}' "$KEY")" "$BASE/api/v1/reveal"
GOT="$(printf '{"key":"%s","confirm":true,"passphrase":"correct horse"}' "$KEY" \
  | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/reveal" | json '["value"]')"
[ "$GOT" = "protected" ] && ok "the right passphrase still works after failures" || bad "got '$GOT'"

head "Secrets are refused in the URL"
for PARAM in secret password passphrase value token; do
  expect_status 400 "?$PARAM= is rejected" -X POST "$BASE/api/v1/secret?$PARAM=hunter2"
done
curl -sS -X POST "$BASE/api/v1/secret?password=hunter2" | grep -qi "compromised" \
  && ok "the rejection tells the caller to rotate the value" || bad "the rejection does not mention rotating"

head "The machine-readable spec is served"
curl -fsS "$BASE/api/v1/openapi.json" | python3 -c 'import sys,json;json.load(sys.stdin)' \
  && ok "openapi.json is valid JSON" || bad "openapi.json is not valid JSON"
expect_status 200 "the live limits endpoint answers" "$BASE/api/v1/config"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
