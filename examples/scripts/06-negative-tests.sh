#!/usr/bin/env bash
# Step 6 - Negative tests: things that must be refused, for both exchange lanes.
#
# 01-05 show the happy path. This script sends bad input and checks that each attempt is rejected
# with the expected HTTP status and error, so you can see where each control sits:
#
#   Async lane      client API input checks, authorisation, contract lifecycle, L1 failure after
#                   acceptance, concurrent sends, retention purge, and (against the receiver's peer
#                   endpoint) signature checks, replay protection, unauthorised senders, unsafe file
#                   names, and receiver-side schema / anonymisation enforcement.
#   Sync lane       client API input checks, authorisation, contract lifecycle, idempotency keys,
#                   single application of PII rules, nonce replay, receiver-side enforcement,
#                   responder failure and timeout, circuit breaker (opt-in).
#   Node security   console pages without a session, admin API without a token, forged token,
#                   peer handshake header on a non-peer function, first-time setup with a wrong token.
#
# The full list of scenarios, with the status each one expects, is in README.md.
#
# It leaves your example contracts alone. Contracts it has to suspend, purge or point at a broken
# responder are created fresh on every run (named "Negative Test ... <timestamp>"), together with
# throw-away applications. Peer calls are signed with Node A's key from the state directory, as a
# real partner would sign them. Requires 01-03 to have run.
#
# Usage:
#   ./06-negative-tests.sh                      run every scenario except the slow one
#   ./06-negative-tests.sh --circuit-breaker    also trip the circuit breaker (adds ~70 s)
#
# Exit status is 0 only if every scenario behaved as expected.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

RUN_BREAKER=0
[ "${1:-}" = "--circuit-breaker" ] && RUN_BREAKER=1

# Timezone of the nodes' JVM (the image sets Asia/Kolkata). Replay protection compares message
# timestamps in that zone, so the "fresh timestamp" below must be written in it.
NODE_TZ="${NODE_TZ:-Asia/Kolkata}"
RUN_ID="$(date +%s)"
PAYLOADS="$EXAMPLES_DIR/payloads"

ASYNC_CID="$(state_need async_contract_id ./03-define-contract.sh)" || exit 1
SYNC_CID="$(state_need sync_contract_id ./03-define-contract.sh)" || exit 1
VALID_ASYNC="$(jq -c . "$PAYLOADS/async-sample.json")"
VALID_SYNC="$(jq -c . "$PAYLOADS/sync-sample.json")"

# --- tiny assertion harness ---------------------------------------------------------------
PASSED=0; FAILED=0; LINES=()
# expect ID DESCRIPTION CODE_REGEX [BODY_REGEX]   - judges the last CODE/RESP
expect() {
  local id="$1" desc="$2" want="$3" body="${4:-}" good=1
  [[ "$CODE" =~ ^($want)$ ]] || good=0
  if [ -n "$body" ] && ! printf '%s' "$RESP" | grep -Eqi -- "$body"; then good=0; fi
  local msg; msg="$(printf '%s' "$RESP" | jq -r '.message // .error // empty' 2>/dev/null | head -c 110)"
  if [ "$good" = 1 ]; then
    PASSED=$((PASSED+1)); ok "$id  $desc  -> HTTP $CODE"
    LINES+=("PASS  $id  $desc")
  else
    FAILED=$((FAILED+1)); printf '    %s✘%s %s  %s\n' "$_R" "$_N" "$id" "$desc" >&2
    printf '        expected HTTP %s%s, got HTTP %s: %s\n' "$want" "${body:+ and /$body/}" "$CODE" "${msg:-$RESP}" >&2
    LINES+=("FAIL  $id  $desc (HTTP $CODE)")
  fi
}
# expect_status ID DESCRIPTION WANT_STATUS BODY_REGEX   - judges $STATUS / $RESP of a polled transfer
expect_status() {
  local id="$1" desc="$2" want="$3" body="${4:-}" good=1
  [ "$STATUS" = "$want" ] || good=0
  if [ -n "$body" ] && ! printf '%s' "$RESP" | grep -Eqi -- "$body"; then good=0; fi
  if [ "$good" = 1 ]; then
    PASSED=$((PASSED+1)); ok "$id  $desc  -> status $STATUS"
    LINES+=("PASS  $id  $desc")
  else
    FAILED=$((FAILED+1)); printf '    %s✘%s %s  %s\n' "$_R" "$_N" "$id" "$desc" >&2
    printf '        expected status %s%s, got %s: %s\n' "$want" "${body:+ and /$body/}" "${STATUS:-<none>}" "$(printf '%s' "$RESP" | jq -r '.error // .message // .' 2>/dev/null | head -c 110)" >&2
    LINES+=("FAIL  $id  $desc (status ${STATUS:-none})")
  fi
}

# --- helpers --------------------------------------------------------------------------------
b64s() { printf '%s' "$1" | base64 | tr -d '\n'; }

new_contract() {   # kind name [responder_url] [timeout_ms] [retention_days] [rules_json]  -> prints contract_id
  local kind="$1" name="$2" url="${3:-}" tmo="${4:-10000}" ret="${5:-30}" body cid rules="${6:-}"
  if [ -z "$rules" ]; then
    if [ "$kind" = sync ]; then rules='{"mobile":"MASK"}'; else rules='{"applicant_id":"HASH","mobile":"MASK"}'; fi
  fi
  if [ "$kind" = sync ]; then
    body="$(jq -n --arg n "$name" --argjson s "$(cat "$PAYLOADS/sync-contract-schema.json")" \
            --arg url "$url" --argjson t "$tmo" --argjson r "$rules" '{
      _func:"create_contract", name:$n, description:"Created by 06-negative-tests.sh",
      interaction_type:"sync", schema_definition:$s,
      metadata:{format:"json", sync_responder_url:$url, sync_timeout_ms:$t,
                governance_rules:{pii_anonymization:$r}}, pii_fields:($r|keys)}')"
  else
    body="$(jq -n --arg n "$name" --argjson s "$(cat "$PAYLOADS/async-contract-schema.json")" \
            --argjson r "$rules" --argjson d "$ret" '{
      _func:"create_contract", name:$n, description:"Created by 06-negative-tests.sh",
      interaction_type:"async", schema_definition:$s,
      metadata:{format:"json", governance_rules:{pii_anonymization:$r}},
      retention_policy_days:$d, pii_fields:($r|keys)}')"
  fi
  admin "$NODE_B_URL" "$TOKEN_B" contracts "$body"
  cid="$(printf '%s' "$RESP" | jq -r .contract_id)"
  admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$cid" --arg n "$NODE_A_ID" '{_func:"invite_node",contract_id:$c,node_id:$n}')"
  admin "$NODE_A_URL" "$TOKEN_A" contracts "$(jq -n --arg c "$cid" '{_func:"accept_contract",contract_id:$c}')"
  printf '%s' "$cid"
}

new_app() {   # name contract_id...  -> sets APP_KEY / APP_SECRET (Node A application)
  local name="$1"; shift
  local ids; ids="$(printf '%s\n' "$@" | jq -R . | jq -sc 'map(select(length>0))')"
  admin "$NODE_A_URL" "$TOKEN_A" apps "$(jq -n --arg n "$name" --argjson c "$ids" \
    '{_func:"create_app",name:$n,description:"Created by 06-negative-tests.sh",authorized_contract_ids:$c}')"
  local app_id; app_id="$(printf '%s' "$RESP" | jq -r .id)"
  admin "$NODE_A_URL" "$TOKEN_A" apps "$(jq -n --arg a "$app_id" '{_func:"generate_api_key",app_id:$a}')"
  APP_KEY="$(printf '%s' "$RESP" | jq -r .api_key)"; APP_SECRET="$(printf '%s' "$RESP" | jq -r .api_secret)"
}

send_async() {   # contract_id file_name file_data_b64  (as the authorised test app)
  client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$1" --arg n "$2" --arg d "$3" \
    '{_func:"initiate_transfer",contract_id:$c,file_name:$n,file_data:$d}')"
}
call_sync() {    # contract_id payload_json [key] [secret]
  client "$NODE_A_URL" "${3:-$APP_KEY}" "${4:-$APP_SECRET}" "$(jq -n --arg c "$1" --argjson p "$2" --arg i "neg-$RUN_ID-$RANDOM" \
    '{_func:"execute_sync_request",contract_id:$c,request_payload:$p,idempotency_key:$i}')"
}
wait_transfer() {   # transfer_id -> sets STATUS, RESP once terminal
  _poll() {
    client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg t "$1" '{_func:"get_transfer_status",transfer_id:$t}')"
    STATUS="$(printf '%s' "$RESP" | jq -r '.status // empty')"
    case "$STATUS" in Delivered|Failed|Received) return 0 ;; *) return 1 ;; esac
  }
  wait_for _poll "$1" || true
}

# peer NODE_URL ROUTE BODY - call a peer endpoint the way a partner node does: handshake header plus a
# signature made with the sender's identity key. Overrides (environment) let a test break one thing:
#   PEER_SIGN=0            send no signature        PEER_NODE=ID      claim to be another node
#   PEER_KEY=file          sign with another key    PEER_TS_SKEW_MS=n shift the timestamp
#   PEER_REQID=uuid        reuse a request id       PEER_TARGET=ID    address another node
peer() {
  local url="$1" route="$2" body func ts reqid hash node target canonical sig args=()
  body="$(printf '%s' "$3" | jq -c .)"
  func="$(printf '%s' "$body" | jq -r '._func // ""')"
  node="${PEER_NODE:-$NODE_A_ID}"; target="${PEER_TARGET-$NODE_B_ID}"
  ts="$(( $(date +%s%3N) + ${PEER_TS_SKEW_MS:-0} ))"
  reqid="${PEER_REQID:-$(cat /proc/sys/kernel/random/uuid)}"
  hash="$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
  args=("X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1" "X-DX-FUNCTION: $func")
  if [ "${PEER_SIGN:-1}" = 1 ]; then
    canonical="$(printf 'DX-P2P-SIG-V1\n%s\n%s\n%s\n%s\n%s\n%s' "$node" "$target" "$func" "$ts" "$reqid" "$hash")"
    sig="$(printf '%s' "$canonical" | openssl dgst -sha256 -sign "${PEER_KEY:-$STATE_DIR/node_a.key}" | base64 | tr -d '\n')"
    args+=("X-DX-NODE-ID: $node" "X-DX-TARGET-NODE-ID: $target" "X-DX-TIMESTAMP: $ts" "X-DX-REQUEST-ID: $reqid" "X-DX-SIGNATURE: $sig")
  fi
  post_json "$url/api/admin/$2" "$body" "${args[@]}"
}

# --- setup ----------------------------------------------------------------------------------
step "Preparing (fresh contracts and a throw-away application)"
TOKEN_A="$(login "$NODE_A_URL")" || exit 1; TOKEN_B="$(login "$NODE_B_URL")" || exit 1
C_ASYNC_LIFE="$(new_contract async "Negative Test Async Lifecycle $RUN_ID")" || exit 1
C_SYNC_LIFE="$(new_contract sync  "Negative Test Sync Lifecycle $RUN_ID" "http://mock-responder:8099/eligibility")" || exit 1
C_SYNC_DEAD="$(new_contract sync  "Negative Test Sync Dead Responder $RUN_ID" "http://127.0.0.1:1/none" 3000)" || exit 1
C_SYNC_SLOW="$(new_contract sync  "Negative Test Sync Timeout $RUN_ID" "http://10.255.255.1:8099/none" 2000)" || exit 1
C_ASYNC_RET="$(new_contract async "Negative Test Async Retention $RUN_ID" "" 10000 0)" || exit 1
C_ASYNC_PEER="$(new_contract async "Negative Test Async Peer $RUN_ID")" || exit 1
C_SYNC_HASH="$(new_contract sync  "Negative Test Sync Hash $RUN_ID" "http://mock-responder:8099/eligibility" 10000 30 '{"customer_id":"HASH","mobile":"MASK"}')" || exit 1
C_SYNC_PEER="$(new_contract sync  "Negative Test Sync Peer $RUN_ID" "http://mock-responder:8099/eligibility")" || exit 1
# an application that is authorised for nothing
new_app "negative-tests-noauth-$RUN_ID" || exit 1; NOAUTH_KEY="$APP_KEY"; NOAUTH_SECRET="$APP_SECRET"
new_app "negative-tests-$RUN_ID" "$ASYNC_CID" "$SYNC_CID" "$C_ASYNC_LIFE" "$C_SYNC_LIFE" "$C_SYNC_DEAD" "$C_SYNC_SLOW" \
        "$C_ASYNC_RET" "$C_ASYNC_PEER" "$C_SYNC_HASH" "$C_SYNC_PEER" || exit 1
ok "8 extra contracts, 2 applications"
RANDOM_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"

# =============================== ASYNC LANE ===================================================
step "Async lane - client API: authentication"
post_json "$NODE_A_URL/api/client/dx" '{"_func":"list_contracts"}'
expect A01 "no API key headers" 401
client "$NODE_A_URL" "$APP_KEY" "wrong-secret" '{"_func":"list_contracts"}'
expect A02 "wrong API secret" 401
client "$NODE_A_URL" "dx_no_such_key" "$APP_SECRET" '{"_func":"list_contracts"}'
expect A03 "unknown API key" 401

step "Async lane - client API: input validation"
send_async "$ASYNC_CID" "a-$RUN_ID.json" "!!!not base64!!!"
expect A04 "file_data is not Base64" 400 "base64"
send_async "$ASYNC_CID" "a-$RUN_ID.json" "$(b64s 'this is { not json')"
expect A05 "file_data is not valid JSON (fail-fast, contract format=json)" 400 "json"
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$ASYNC_CID" '{_func:"initiate_transfer",contract_id:$c}')"
expect A06 "file_name and file_data missing" 400 "required"
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" '{"_func":"no_such_function"}'
expect A07 "unknown function" 400 "unknown"

step "Async lane - client API: authorisation"
send_async "$RANDOM_UUID" "a-$RUN_ID.json" "$(b64s "$VALID_ASYNC")"
expect A08 "contract does not exist" 403
client "$NODE_A_URL" "$NOAUTH_KEY" "$NOAUTH_SECRET" "$(jq -n --arg c "$ASYNC_CID" --arg d "$(b64s "$VALID_ASYNC")" \
  '{_func:"initiate_transfer",contract_id:$c,file_name:"a.json",file_data:$d}')"
expect A09 "application not authorised for the contract" 403
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg t "$RANDOM_UUID" '{_func:"get_transfer_status",transfer_id:$t}')"
expect A10 "status of a transfer that is not yours / does not exist" 403
send_async "$SYNC_CID" "a-$RUN_ID.json" "$(b64s "$VALID_ASYNC")"
expect A10b "async transfer on a sync contract" "400|403|500"

step "Async lane - unsafe file names (path traversal)"
i=0
for n in "../../../../tmp/dx-pwned" "/etc/dx-pwned" "sub/dir.json" '..\\evil.json' ".."; do
  i=$((i+1))
  send_async "$ASYNC_CID" "$n" "$(b64s "$VALID_ASYNC")"
  expect "A11.$i" "file_name '$n' rejected by the sender API" 400 "file_name"
done
send_async "$ASYNC_CID" "ok-$RUN_ID.json" "$(b64s "$VALID_ASYNC")"
expect A12 "plain file_name still accepted (control)" 201

step "Async lane - contract rules enforced after acceptance"
BAD='{"applicant_id":"A-1","product":"not-a-product","amount":"lots"}'
send_async "$ASYNC_CID" "bad-$RUN_ID.json" "$(b64s "$BAD")"
expect A13a "schema-violating payload is accepted for processing" 201
wait_transfer "$(printf '%s' "$RESP" | jq -r .transfer_id)"
expect_status A13b "...then fails L1 validation before leaving the node" Failed "valid|schema|contract|required|violation"

step "Async lane - receiver peer endpoint (signed as Node A)"
FRESH_TS="$(TZ="$NODE_TZ" date '+%Y-%m-%d %H:%M:%S.000')"
stream() {   # sender file_name seq timestamp [contract] [payload_json] [transfer_id]
  jq -n --arg t "${7:-$(cat /proc/sys/kernel/random/uuid)}" --arg c "${5:-$ASYNC_CID}" --arg s "$1" --arg f "$2" \
        --arg d "$(b64s "${6:-$GOVERNED_ASYNC}")" --argjson q "$3" --arg ts "$4" \
    '{_func:"receive_transfer_stream",transfer_id:$t,contract_id:$c,sender_node_id:$s,file_name:$f,file_data:$d,sequence_number:$q,message_timestamp:$ts}'
}
# what a sender's node would transmit after governance (hash of "A-1000", masked mobile)
GOVERNED_ASYNC="$(jq -nc --arg h "$(printf 'A-1000' | sha256sum | cut -d' ' -f1)" \
  '{applicant_id:$h,mobile:"****3210",product:"loan",amount:250000}')"

peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "../../../../tmp/dx-pwned-$RUN_ID" 999999 "$FRESH_TS")"
expect R01 "path-traversing file_name from a peer" 400 "file_name"
peer "$NODE_B_URL" transfers "$(stream "NODE-NOT-A-PARTICIPANT" "r.json" 999999 "$FRESH_TS")"
expect R02 "body names a node that is not a participant of the contract" 401 "signer|registered|sender_node_id"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "r.json" 999999 "2020-01-01 00:00:00.000")"
expect R03 "message timestamp outside the 5-minute window (stale replay)" 403 "replay|drift"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "r.json" 0 "$FRESH_TS")"
expect R04 "sequence number not greater than the last received (replay)" 403 "replay|sequence"
post_json "$NODE_B_URL/api/admin/transfers" "$(stream "$NODE_A_ID" "r.json" 999999 "$FRESH_TS")"
expect R05 "same stream call without the peer handshake header" 401

step "Peer authentication (signatures)"
BODY="$(stream "$NODE_A_ID" "r.json" 0 "$FRESH_TS")"
PEER_SIGN=0 peer "$NODE_B_URL" transfers "$BODY"
expect P01 "handshake header but no signature" 401 "not signed"
PEER_KEY="$STATE_DIR/node_b.key" peer "$NODE_B_URL" transfers "$BODY"
expect P02 "signed with a key that is not Node A's" 401 "signature"
PEER_TS_SKEW_MS=-600000 peer "$NODE_B_URL" transfers "$BODY"
expect P03 "signature timestamp 10 minutes old" 401 "window"
RID="$(cat /proc/sys/kernel/random/uuid)"
PEER_REQID="$RID" peer "$NODE_B_URL" transfers "$BODY"
PEER_REQID="$RID" peer "$NODE_B_URL" transfers "$BODY"
expect P04 "same request id used twice (captured request replayed)" 401 "replay|already used"
PEER_TARGET="NODE-SOMEONE-ELSE" peer "$NODE_B_URL" transfers "$BODY"
expect P05 "request addressed to a different node" 401 "different node"
PEER_NODE="$NODE_B_ID" peer "$NODE_B_URL" transfers "$BODY"
expect P06 "a node signing as another partner (wrong key for that identity)" 401 "signature|registered"
peer "$NODE_B_URL" transfers "$(stream "$NODE_B_ID" "r.json" 0 "$FRESH_TS")"
expect P07 "body names a different sender than the signer" 401 "sender_node_id"
PEER_SIGN=0 peer "$NODE_B_URL" partners '{"_func":"probe"}'
expect P08 "probe (bootstrap) is the one call that may be unsigned" 200

step "Async lane - receiver enforces its own contract"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "v.json" 1 "$FRESH_TS" "$C_ASYNC_PEER" \
  '{"applicant_id":"x","mobile":"****3210","product":"not-a-product","amount":"lots"}')"
expect V01 "payload breaks the receiver's schema (a sender skipped L1)" 400 "contract violation"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "v.json" 1 "$FRESH_TS" "$C_ASYNC_PEER" \
  '{"applicant_id":"A-1000","mobile":"9876543210","product":"loan","amount":1}')"
expect V02 "PII sent in clear: applicant_id not hashed, mobile not masked (a sender skipped L2)" 400 "anonymised"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "v.json" 1 "$FRESH_TS" "$C_SYNC_PEER")"
expect V03 "contract is a sync contract, not async" 403 "async"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "v.json" 1 "$FRESH_TS" "$RANDOM_UUID")"
expect V04 "contract does not exist on the receiver" 403
TID="$(cat /proc/sys/kernel/random/uuid)"
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "ok-$RUN_ID.json" 1 "$FRESH_TS" "$C_ASYNC_PEER" "$GOVERNED_ASYNC" "$TID")"
expect V05 "control: a correctly governed payload is accepted" 200
peer "$NODE_B_URL" transfers "$(stream "$NODE_A_ID" "ok-$RUN_ID.json" 1 "$FRESH_TS" "$C_ASYNC_PEER" "$GOVERNED_ASYNC" "$TID")"
expect V06 "same transfer delivered again after a lost answer: acknowledged, not stored twice" 200 "duplicate"

step "Async lane - ordering and delivery"
PIDS=()
for i in 1 2 3 4 5 6; do
  ( client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$ASYNC_CID" --arg n "par-$RUN_ID-$i.json" --arg d "$(b64s "$VALID_ASYNC")" \
      '{_func:"initiate_transfer",contract_id:$c,file_name:$n,file_data:$d}')"
    printf '%s' "$RESP" | jq -r .transfer_id > "$STATE_DIR/par-$i.tid" ) &
  PIDS+=($!)
done
wait "${PIDS[@]}"
DELIVERED=0
for i in 1 2 3 4 5 6; do
  wait_transfer "$(cat "$STATE_DIR/par-$i.tid")"
  [ "$STATUS" = Delivered ] && DELIVERED=$((DELIVERED+1))
  rm -f "$STATE_DIR/par-$i.tid"
done
CODE=200; RESP="{\"message\":\"delivered=$DELIVERED\"}"
expect A15 "6 transfers started at the same moment on one contract all arrive (sequence numbers never collide)" 200 "delivered=6"

step "Async lane - retention"
send_async "$C_ASYNC_RET" "ret-$RUN_ID.json" "$(b64s "$VALID_ASYNC")"
RET_TID="$(printf '%s' "$RESP" | jq -r .transfer_id)"
wait_transfer "$RET_TID"
admin "$NODE_B_URL" "$TOKEN_B" transfers "$(jq -n --arg t "$RET_TID" '{_func:"get_transfer_payload",transfer_id:$t}')"
before="$(printf '%s' "$RESP" | jq -r .success)"
admin "$NODE_B_URL" "$TOKEN_B" transfers '{"_func":"run_maintenance"}'
CODE=200
expect A16a "maintenance run on the receiver reports what it purged" 200 "payloads_purged"
admin "$NODE_B_URL" "$TOKEN_B" transfers "$(jq -n --arg t "$RET_TID" '{_func:"get_transfer_payload",transfer_id:$t}')"
CODE=200; RESP="{\"message\":\"before=$before after=$(printf '%s' "$RESP" | jq -r .success)\"}"
expect A16b "contract retention_policy_days=0: stored payload deleted by the purge" 200 "before=true after=false"
step "Async lane - contract lifecycle"
admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$C_ASYNC_LIFE" '{_func:"deactivate_contract",contract_id:$c}')"
send_async "$C_ASYNC_LIFE" "life-$RUN_ID.json" "$(b64s "$VALID_ASYNC")"
expect A14 "contract suspended by the receiver" 403

# =============================== SYNC LANE ====================================================
step "Sync lane - client API"
call_sync "$SYNC_CID" "$VALID_SYNC" "$APP_KEY" "wrong-secret"
expect S01 "wrong API secret" 401
call_sync "$SYNC_CID" '{"customer_id":"C-001"}'
expect S02 "request breaks the contract schema (L1)" 400 "contract violation|required"
call_sync "$SYNC_CID" '{"customer_id":"C-1","mobile":123,"product":"loan"}'
expect S03 "wrong field type (mobile is a number)" 400 "contract violation|type|string"
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$SYNC_CID" '{_func:"execute_sync_request",contract_id:$c}')"
expect S04 "request_payload missing" 400 "request_payload"
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" '{"_func":"execute_sync_request","request_payload":{"a":1}}'
expect S05 "contract_id missing" 400 "contract_id"
call_sync "$RANDOM_UUID" "$VALID_SYNC"
expect S06 "contract does not exist" 403
call_sync "$ASYNC_CID" "$VALID_SYNC"
expect S07 "contract is async, not sync" 403 "non-sync|sync"
call_sync "$SYNC_CID" "$VALID_SYNC" "$NOAUTH_KEY" "$NOAUTH_SECRET"
expect S08 "application not authorised for the contract" 403
call_sync "$SYNC_CID" "$VALID_SYNC"
expect S09 "control: a valid call still succeeds" 200 "ok"

step "Sync lane - idempotency keys and PII rules applied once"
IDEM="neg-idem-$RUN_ID"
idem_call() { client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$SYNC_CID" --argjson p "$1" --arg i "$IDEM" \
  '{_func:"execute_sync_request",contract_id:$c,request_payload:$p,idempotency_key:$i}')"; }
idem_call "$VALID_SYNC"
expect S15a "first call with a new idempotency key runs" 200 'duration_ms[^0-9]*[1-9]'
idem_call "$VALID_SYNC"
expect S15b "same key and same request: recorded answer returned, partner not called again" 200 "idempotent_replay"
idem_call '{"customer_id":"C-999","mobile":"9876543210","product":"loan"}'
expect S15c "same key with a different request" 400 "idempotency_key"
admin "$NODE_B_URL" "$TOKEN_B" transfers '{"_func":"list_sync_audit_logs"}'
N_B="$(printf '%s' "$RESP" | jq --arg k "$IDEM" '[.data[]|select(.idempotency_key==$k)]|length')"
CODE=200; RESP="{\"message\":\"receiver_rows=$N_B\"}"
expect S15d "the partner executed it once (one audit row on the receiver)" 200 "receiver_rows=1"

HASHED="$(printf 'C-001' | sha256sum | cut -d' ' -f1)"
client "$NODE_A_URL" "$APP_KEY" "$APP_SECRET" "$(jq -n --arg c "$C_SYNC_HASH" --arg i "neg-hash-$RUN_ID" \
  '{_func:"execute_sync_request",contract_id:$c,idempotency_key:$i,request_payload:{customer_id:"C-001",mobile:"9876543210",product:"loan"}}')"
expect S16a "contract with a HASH rule: call succeeds" 200
admin "$NODE_B_URL" "$TOKEN_B" transfers '{"_func":"list_sync_audit_logs"}'
SEEN_ID="$(printf '%s' "$RESP" | jq -r --arg k "neg-hash-$RUN_ID" '[.data[]|select(.idempotency_key==$k)][0].request_payload.customer_id')"
CODE=200; RESP="{\"message\":\"receiver_saw=$SEEN_ID\"}"
expect S16b "receiver saw SHA-256 of the id exactly once (not a hash of a hash)" 200 "receiver_saw=$HASHED"

step "Sync lane - receiver peer endpoint (signed as Node A)"
NONCE="neg-nonce-$RUN_ID"
GOVERNED_SYNC='{"customer_id":"C-001","mobile":"****3210","product":"loan"}'
sync_in() {   # nonce contract_id [payload]
  jq -n --arg n "$1" --arg c "$2" --argjson p "${3:-$GOVERNED_SYNC}" \
    '{_func:"receive_sync_request",contract_id:$c,nonce:$n,sender_node_id:"'"$NODE_A_ID"'",idempotency_key:"neg",request_payload:$p}'
}
peer "$NODE_B_URL" transfers "$(sync_in "$NONCE" "$SYNC_CID")"
expect R10 "first use of a nonce" 200
peer "$NODE_B_URL" transfers "$(sync_in "$NONCE" "$SYNC_CID")"
expect R11 "same nonce again (replay)" 403 "replay|nonce"
peer "$NODE_B_URL" transfers "$(jq -n --arg c "$SYNC_CID" '{_func:"receive_sync_request",contract_id:$c,sender_node_id:"'"$NODE_A_ID"'"}')"
expect R12 "nonce missing" 400 "nonce"
post_json "$NODE_B_URL/api/admin/transfers" "$(sync_in "neg-nonce-b-$RUN_ID" "$SYNC_CID")"
expect R13 "same call without the peer handshake header" 401
PEER_SIGN=0 peer "$NODE_B_URL" transfers "$(sync_in "neg-nonce-c-$RUN_ID" "$SYNC_CID")"
expect R14 "same call, handshake header but no signature" 401 "not signed"
peer "$NODE_B_URL" transfers "$(sync_in "neg-nonce-d-$RUN_ID" "$SYNC_CID" '{"customer_id":"C-001"}')"
expect R15 "request breaks the receiver's schema" 400 "contract violation"
peer "$NODE_B_URL" transfers "$(sync_in "neg-nonce-e-$RUN_ID" "$SYNC_CID" '{"customer_id":"C-001","mobile":"9876543210","product":"loan"}')"
expect R16 "mobile sent in clear: the caller skipped the mask" 400 "anonymised"

step "Sync lane - responder failures (calls to Node B's responder go wrong)"
call_sync "$C_SYNC_DEAD" "$VALID_SYNC"
expect S10 "responder refuses the connection" "5[0-9][0-9]"
call_sync "$C_SYNC_SLOW" "$VALID_SYNC"
expect S11 "responder does not answer within sync_timeout_ms (2 s)" "5[0-9][0-9]"
admin "$NODE_A_URL" "$TOKEN_A" transfers '{"_func":"list_sync_audit_logs"}'
ST="$(printf '%s' "$RESP" | jq -r --arg c "$C_SYNC_DEAD" '[.data[]|select(.contract_id==$c)][0].status // empty')"
CODE=200; RESP="{\"message\":\"audit status=$ST\"}"
expect S12 "the failed call is in the caller's audit log" 200 "ERROR|TIMEOUT|FAIL"
call_sync "$SYNC_CID" "$VALID_SYNC"   # one success clears the failure count again
expect S13 "healthy contract still works after two failures" 200

step "Sync lane - contract lifecycle"
admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$C_SYNC_LIFE" '{_func:"deactivate_contract",contract_id:$c}')"
call_sync "$C_SYNC_LIFE" "$VALID_SYNC"
expect S14 "contract suspended by the receiver" 403

if [ "$RUN_BREAKER" = 1 ]; then
  step "Sync lane - circuit breaker (opens after 5 consecutive failures per partner; 60 s cooldown)"
  for i in 1 2 3 4 5; do call_sync "$C_SYNC_DEAD" "$VALID_SYNC"; done
  call_sync "$C_SYNC_DEAD" "$VALID_SYNC"
  expect S20 "6th call fails fast: circuit is open" "5[0-9][0-9]" "circuit"
  call_sync "$SYNC_CID" "$VALID_SYNC"
  expect S21 "the breaker is per partner: the healthy contract is refused too" "5[0-9][0-9]" "circuit"
  info "waiting 62 s for the cooldown..."
  sleep 62
  call_sync "$SYNC_CID" "$VALID_SYNC"
  expect S22 "after the cooldown a healthy call goes through and closes the breaker" 200
else
  info "(skipped) circuit breaker - run with --circuit-breaker (adds about 70 s)"
fi

step "Editing contracts"
upd() { post_json "$NODE_B_URL/api/admin/contracts" "$1" "Authorization: Bearer $TOKEN_B"; }
upd "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"update_contract",contract_id:$c,name:"Negative Test Sync Peer (edited)",sync_timeout_ms:7000,retention_policy_days:45}')"
expect E01 "receiver edits name, timeout and retention of an Active sync contract" 200 "sync_timeout_ms"
admin "$NODE_A_URL" "$TOKEN_A" contracts "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"get_contract",contract_id:$c}')"
CODE=200; RESP="{\"message\":\"sender_copy=$(printf '%s' "$RESP" | jq -r '[.name, .metadata.sync_timeout_ms, .retention_policy_days]|join("|")')\"}"
expect E02 "the participant's copy follows (name, timeout, retention)" 200 "sender_copy=Negative Test Sync Peer \\(edited\\)\\|7000\\|45"
upd "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"update_contract",contract_id:$c,sync_responder_url:"http://mock-responder:8099/other"}')"
expect E03 "receiver changes the responder URL of an Active contract" 200
admin "$NODE_A_URL" "$TOKEN_A" contracts "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"get_contract",contract_id:$c}')"
CODE=200; RESP="{\"message\":\"leaked=$(printf '%s' "$RESP" | jq -r '.metadata.sync_responder_url // "no"')\"}"
expect E04 "the responder URL is never sent to the participant" 200 "leaked=no"
upd "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"update_contract",contract_id:$c,sync_responder_url:"ftp://nope"}')"
expect E05 "responder URL that is not http(s)" 400 "http"
upd "$(jq -n --arg c "$C_SYNC_PEER" '{_func:"update_contract",contract_id:$c,sync_responder_url:""}')"
expect E06 "responder URL cleared on a sync contract" 400 "http"
upd "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"update_contract",contract_id:$c,sync_timeout_ms:5000}')"
expect E07 "sync settings on an async contract" 400 "sync contracts only"
upd "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"update_contract",contract_id:$c,pii_anonymization:{applicant_id:"NONE"}}')"
expect E08 "terms (anonymisation rules) of an Active, invited contract are frozen" 403 "cannot change"
upd "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"update_contract",contract_id:$c}')"
expect E09 "nothing to change" 400 "nothing"
post_json "$NODE_A_URL/api/admin/contracts" "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"update_contract",contract_id:$c,name:"hijack"}')" "Authorization: Bearer $TOKEN_A"
expect E10 "a participant (not the receiver) tries to edit" 403 "receiving node"
upd "$(jq -n --arg c "$C_ASYNC_LIFE" '{_func:"update_contract",contract_id:$c,name:"too late"}')"
expect E11 "a Suspended contract" 403 "Suspended"
admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg n "Negative Test Draft $RUN_ID" --argjson s "$(cat "$PAYLOADS/async-contract-schema.json")" \
  '{_func:"create_contract",name:$n,interaction_type:"async",schema_definition:$s,metadata:{format:"json",governance_rules:{pii_anonymization:{mobile:"MASK"}}},pii_fields:["mobile"]}')"
DRAFT="$(printf '%s' "$RESP" | jq -r .contract_id)"
upd "$(jq -n --arg c "$DRAFT" '{_func:"update_contract",contract_id:$c,pii_anonymization:{mobile:"HASH",applicant_id:"HASH"},pii_fields:["mobile","applicant_id"]}')"
expect E12 "a Draft nobody was invited to: anonymisation rules can still change" 200 "pii_anonymization"
peer "$NODE_B_URL" contracts "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"notify_contract_suspended",contract_id:$c}')"
expect E13 "a partner that does not own the contract tells this node to suspend it (peer)" 403 "receiving node"
peer "$NODE_B_URL" contracts "$(jq -n --arg c "$C_ASYNC_PEER" '{_func:"receive_contract_update",contract_id:$c,name:"hijack"}')"
expect E14 "a partner that does not own the contract pushes an update (peer)" 403 "receiving node"
peer "$NODE_B_URL" contracts "$(jq -n --arg c "$C_ASYNC_PEER" --arg n "$NODE_B_ID" '{_func:"confirm_invitation",contract_id:$c,node_id:$n}')"
expect E15 "a partner confirms an invitation on behalf of another node (peer)" 403 "signing node"

# =============================== NODE SECURITY ================================================
step "Node security"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$NODE_A_URL/dashboard.html")"; RESP="{}"
expect N01 "console page without a session redirects to login" 302
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$NODE_A_URL/index.html")"; RESP="{}"
expect N02 "login page stays public" 200
post_json "$NODE_A_URL/api/admin/contracts" '{"_func":"list_contracts"}'
expect N03 "admin API without a JWT" 401
post_json "$NODE_A_URL/api/admin/contracts" '{"_func":"list_contracts"}' "X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1"
expect N04 "peer handshake header does not unlock admin functions" 401
post_json "$NODE_A_URL/api/admin/contracts" '{"_func":"list_contracts"}' "Authorization: Bearer not.a.jwt"
expect N05 "malformed JWT" 401
post_json "$NODE_A_URL/api/admin/registeradmin" \
  '{"_func":"register_admin","setup_token":"wrong-token","node_id":"X","fqdn":"x","username":"u","email":"u@example.org","password":"Passw0rd!x"}'
expect N06 "first-time setup with a wrong setup token" "401|409"
post_json "$NODE_A_URL/api/admin/login" "$(jq -n --arg e "$ADMIN_EMAIL" '{_func:"admin_login",email:$e,password:"definitely-wrong"}')"
expect N07 "login with a wrong password" "401|403"
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
FORGED_H="$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)"
FORGED_P="$(printf '{"sub":"%s","name":"admin","role":"admin","exp":4102444800}' "$ADMIN_EMAIL" | b64url)"
FORGED_S="$(printf '%s.%s' "$FORGED_H" "$FORGED_P" | openssl dgst -sha256 -hmac "tsi-dx-node-identity-governance-stable-key-2026" -binary | b64url)"
post_json "$NODE_A_URL/api/admin/contracts" '{"_func":"list_contracts"}' "Authorization: Bearer $FORGED_H.$FORGED_P.$FORGED_S"
expect N08 "admin token forged with the old built-in signing key" 401

# =============================== SUMMARY ======================================================
step "Summary"
printf '    %s\n' "${LINES[@]}"
printf '\n    %s passed, %s failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ] || { printf '\n%s✘ %s scenario(s) did not behave as expected%s\n' "$_R" "$FAILED" "$_N" >&2; exit 1; }
printf '\n%s✔ All negative scenarios were rejected as expected%s\n' "$_G" "$_N"
