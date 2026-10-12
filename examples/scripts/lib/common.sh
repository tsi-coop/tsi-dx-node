#!/usr/bin/env bash
# Shared helpers for the TSI DX Node example scripts. Sourced, not executed.
#
# Defaults match docs/guides/local-testing-guide.md (two nodes started with docker-compose.p2p.yml and
# .env.node-a / .env.node-b). Override any of them with environment variables.
#
# Direction used throughout: Node B is the RECEIVER (it authors contracts and, for sync,
# hosts the responder); Node A is the SENDER / caller. This is the receiver-authority model
# described in docs/design/architecture.md.

# --- endpoints and identities -------------------------------------------------------------
NODE_A_URL="${NODE_A_URL:-http://localhost:8082}"
NODE_B_URL="${NODE_B_URL:-http://localhost:8083}"

NODE_A_ID="${NODE_A_ID:-NODE-A-SOUTH}"
NODE_B_ID="${NODE_B_ID:-NODE-B-NORTH}"

# Hostname each node advertises to its partner. It must resolve from the other node's container
# and must be a SAN of the transport certificate (the dev keystore covers these two names).
NODE_A_HOST="${NODE_A_HOST:-node-a-server-1}"
NODE_B_HOST="${NODE_B_HOST:-node-b-server-1}"
P2P_PORT="${P2P_PORT:-8443}"   # container-to-container HTTPS port, not the host-mapped one

# First-time setup tokens (TSI_DX_NODE_BOOTSTRAP_TOKEN on each node; see .env.node-a/.env.node-b)
SETUP_TOKEN_A="${SETUP_TOKEN_A:-dev-node-a-setup-token}"
SETUP_TOKEN_B="${SETUP_TOKEN_B:-dev-node-b-setup-token}"

ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.org}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Passw0rd!x}"   # needs upper, lower, digit and a special char

# Where scripts keep generated keys, certificates and IDs so they can be run one at a time.
# Holds private keys and API secrets: dev/test use only. Delete the directory to start over.
EXAMPLES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${DX_STATE_DIR:-$EXAMPLES_DIR/.state}"
mkdir -p "$STATE_DIR"

# --- output -------------------------------------------------------------------------------
if [ -t 1 ]; then _B=$'\033[1m'; _G=$'\033[32m'; _R=$'\033[31m'; _Y=$'\033[33m'; _N=$'\033[0m'; else _B=; _G=; _R=; _Y=; _N=; fi
step() { printf '\n%s==> %s%s\n' "$_B" "$*" "$_N"; }
ok()   { printf '    %s✔%s %s\n' "$_G" "$_N" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %s!%s %s\n' "$_Y" "$_N" "$*" >&2; }
die()  { printf '%s✘ %s%s\n' "$_R" "$*" "$_N" >&2; exit 1; }

require_tools() {
  local t
  for t in curl jq openssl base64; do
    command -v "$t" >/dev/null 2>&1 || die "Required tool not found: $t"
  done
}

# --- state --------------------------------------------------------------------------------
state_set() { printf '%s' "$2" > "$STATE_DIR/$1"; }
state_get() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1" || true; }
state_need() {
  local v; v="$(state_get "$1")"
  [ -n "$v" ] || die "Missing '$1'. Run $2 first."
  printf '%s' "$v"
}

# --- HTTP ---------------------------------------------------------------------------------
# post_json URL BODY [header ...]  ->  sets RESP (body) and CODE (HTTP status); never exits.
post_json() {
  local url="$1" body="$2"; shift 2
  local args=() h
  for h in "$@"; do args+=(-H "$h"); done
  local out
  out="$(curl -sS -X POST "$url" -H 'Content-Type: application/json' "${args[@]}" -d "$body" -w $'\n%{http_code}' 2>&1)" \
    || die "Cannot reach $url - is the node running?"
  CODE="${out##*$'\n'}"
  RESP="${out%$'\n'*}"
}

# admin NODE_URL TOKEN ENDPOINT BODY  ->  RESP/CODE; dies on HTTP >= 400.
admin() {
  post_json "$1/api/admin/$3" "$4" "Authorization: Bearer $2"
  if [ "${CODE:-0}" -ge 400 ] 2>/dev/null; then
    die "$3 failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .error // .' 2>/dev/null || printf '%s' "$RESP")"
  fi
}

# client NODE_URL KEY SECRET BODY  ->  RESP/CODE (caller decides how to treat errors).
client() {
  post_json "$1/api/client/dx" "$4" "X-API-Key: $2" "X-API-Secret: $3"
}

# login NODE_URL  ->  prints a fresh admin JWT
login() {
  post_json "$1/api/admin/login" \
    "$(jq -n --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{_func:"admin_login",email:$e,password:$p}')"
  [ "$CODE" = "200" ] || die "Login to $1 failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .' 2>/dev/null)"
  printf '%s' "$RESP" | jq -r .token
}

# wait_for CMD... : poll until CMD succeeds (up to WAIT_SECS, default 60)
wait_for() {
  local deadline=$(( $(date +%s) + ${WAIT_SECS:-60} ))
  until "$@"; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}

# b64 FILE -> single-line Base64 (portable across GNU/BSD base64)
b64() { base64 < "$1" | tr -d '\n'; }

# ensure_app_key KIND CONTRACT_ID
# Creates (once) a client application on Node A authorised for the contract, issues an API key
# and stores it in STATE_DIR. Reuses the stored key while it still works.
ensure_app_key() {
  local kind="$1" cid="$2" token key secret
  key="$(state_get "${kind}_api_key")"; secret="$(state_get "${kind}_api_secret")"
  if [ -n "$key" ] && [ -n "$secret" ]; then
    client "$NODE_A_URL" "$key" "$secret" '{"_func":"list_contracts"}'
    if [ "$CODE" = "200" ] && printf '%s' "$RESP" | jq -e --arg c "$cid" 'any(.[]?; .contract_id==$c)' >/dev/null 2>&1; then
      return 0
    fi
  fi
  token="$(login "$NODE_A_URL")" || exit 1
  admin "$NODE_A_URL" "$token" apps \
    "$(jq -n --arg n "example-$kind-app" --arg c "$cid" \
        '{_func:"create_app",name:$n,description:"Created by examples/scripts",authorized_contract_ids:[$c]}')"
  local app_id; app_id="$(printf '%s' "$RESP" | jq -r .id)"
  admin "$NODE_A_URL" "$token" apps "$(jq -n --arg a "$app_id" '{_func:"generate_api_key",app_id:$a}')"
  state_set "${kind}_api_key" "$(printf '%s' "$RESP" | jq -r .api_key)"
  state_set "${kind}_api_secret" "$(printf '%s' "$RESP" | jq -r .api_secret)"
  ok "Application 'example-$kind-app' registered on Node A with a new API key"
}
