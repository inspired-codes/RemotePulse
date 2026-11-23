#!/usr/bin/env bash
# Black-box check of the web image's static serving rules (src/Applications/.../App/Caddyfile)
# against any running instance, a local container or a live host.
#
#   bash scripts/verify-web.sh http://127.0.0.1:8080
#   bash scripts/verify-web.sh https://rmpls.inspired.codes
#   bash scripts/verify-web.sh https://psrun.inspired.codes
#
# Exit code is the number of failed checks.
set -u
BASE="${1:?usage: verify-web.sh <base-url>}"; BASE="${BASE%/}"
fail=0; pass=0

# check <name> <path> <expected status> [header-regex ...]
# Each regex is matched case-insensitively against the start of a response header line. A leading
# "!" means no header line may match. ACCEPT, when set, is sent as Accept-Encoding.
check() {
    local name="$1" path="$2" status="$3"; shift 3
    local hdrs got want ok=1
    hdrs="$(curl -s -o /dev/null -D - --max-time 15 ${ACCEPT:+-H "Accept-Encoding: $ACCEPT"} "$BASE$path" | tr -d '\r')"
    got="$(printf '%s\n' "$hdrs" | head -1 | awk '{print $2}')"
    [ "$got" = "$status" ] || { ok=0; echo "  status: want $status, got ${got:-none}"; }
    for want in "$@"; do
        if [[ "$want" == '!'* ]]; then
            printf '%s\n' "$hdrs" | grep -qiE "^${want#!}" && { ok=0; echo "  unwanted header: ${want#!}"; }
        else
            printf '%s\n' "$hdrs" | grep -qiE "^$want" || { ok=0; echo "  missing header: $want"; }
        fi
    done
    if [ "$ok" = 1 ]; then pass=$((pass+1)); echo "ok   $name"; else fail=$((fail+1)); echo "FAIL $name ($path)"; fi
}

# body_not_html <name> <path>: the response must not be the HTML shell.
body_not_html() {
    if curl -s --max-time 15 "$BASE$2" | head -c 200 | grep -qi '<!doctype html\|<html'; then
        fail=$((fail+1)); echo "FAIL $1 ($2 returned HTML)"
    else
        pass=$((pass+1)); echo "ok   $1"
    fi
}

NOSTORE='cache-control: .*no-store'
NOCACHE='cache-control: .*no-cache'

check "landing page"           /                              200 "$NOSTORE" 'content-type: text/html' 'x-content-type-options: nosniff' '!server:'
check "security page"          /security                      200 "$NOSTORE" 'content-type: text/html' 'x-content-type-options: nosniff' '!server:'
check "security.html"          /security.html                 200 "$NOSTORE" 'content-type: text/html'
check "SPA route /app"         /app                           200 "$NOSTORE" 'content-type: text/html'
check "SPA route /pairing/v1"  /pairing/v1                    200 "$NOSTORE" 'content-type: text/html'
check "SPA route /pairing/v2"  /pairing/v2                    200 "$NOSTORE" 'content-type: text/html'
check "index.html"             /index.html                    200 "$NOSTORE"
check "portal.html"            /portal.html                   200 "$NOSTORE"
check "service-worker.js"      /service-worker.js             200 "$NOSTORE"
check "manifest.json"          /manifest.json                 200 "$NOSTORE"
check "/downloads redirects"   /downloads                     301 'location: /$'
check "/downloads/ redirects"  /downloads/                    301 'location: /$'
check "/portal redirects"      /portal                        301 'location: /$'
check "get-worker.ps1"         /get-worker.ps1                200 "$NOCACHE" 'content-type: text/plain'
check "app.css"                /app.css                       200 "$NOCACHE" 'content-type: text/css'
check "worker-version.json"    /downloads/worker-version.json 200 "$NOCACHE" 'content-type: application/json'
check "missing .ps1 is 404"    /nope.ps1                      404 "$NOSTORE"
check "missing .js is 404"     /js/nope.js                    404 "$NOSTORE"
check "missing .zip is 404"    /downloads/nope.zip            404 "$NOSTORE"
# An error must never inherit the 1-year immutable header of its /_framework/ path.
check "missing framework file" /_framework/nope               404 "$NOSTORE" '!cache-control: .*immutable' '!server:'
body_not_html "get-worker.ps1 is a script, not HTML" /get-worker.ps1

# A fingerprinted framework file, found through the shell page's own references.
fw="$(curl -s --max-time 15 "$BASE/index.html" | grep -oE '_framework/[A-Za-z0-9._-]+\.js' | head -1)"
if [ -n "$fw" ]; then
    check "framework file is immutable" "/$fw" 200 'cache-control: .*immutable' 'cache-control: .*max-age=31536000'
    ACCEPT="br"       check "framework file precompressed (br)"        "/$fw" 200 'content-encoding: br' 'content-type: .*javascript'
    ACCEPT="gzip"     check "framework file precompressed (gzip)"      "/$fw" 200 'content-encoding: gzip'
    ACCEPT="identity" check "framework file plain without Accept-Encoding" "/$fw" 200 '!content-encoding:'
else
    fail=$((fail+1)); echo "FAIL no _framework/*.js reference found in index.html"
fi
ACCEPT="gzip" check "get-worker.ps1 compressed on the fly" /get-worker.ps1 200 'content-encoding: (gzip|zstd)'

echo "---- $pass passed, $fail failed ($BASE)"
exit "$fail"
