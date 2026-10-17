#!/usr/bin/env bash
# Step 7 - Consent channel (CEF-EVENTS).
#
# Every node has a built-in system contract, CEF-EVENTS, that carries Consent Exchange Format (CEF) JSON to
# any Active partner. No contract has to be defined or accepted. This script drives it end to end:
#
#   1. Finds Node B's CEF-EVENTS in Node A's contract list (read-only, system contract).
#   2. Node A sends a consent grant with two purposes; Node B receives it.
#   3. Node A sends the full updated state with one purpose withdrawn, then an erasure request.
#   4. Node B sends the ERASURE_CONFIRMED reply to Node A's CEF-EVENTS.
#   5. Negative checks: malformed events are refused, and CEF-EVENTS cannot be edited.
#
# Requires: curl, jq. Run 01 and 02 first (the nodes must be Active partners). 03 is not needed.
#
# Usage:  ./07-consent-exchange.sh
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

TOKEN_A="$(login "$NODE_A_URL")" || exit 1
TOKEN_B="$(login "$NODE_B_URL")" || exit 1
RUN_ID="$(date +%s)"
FID="f-1001"; PID="p-$RUN_ID"
FAILS=0

cef_contract() {   # cef_contract TOKEN URL OWNER_NODE_ID -> prints the contract id
  admin "$2" "$1" contracts '{"_func":"list_contracts"}'
  printf '%s' "$RESP" | jq -r --arg o "$3" '.[]|select(.name=="CEF-EVENTS" and .receiver_node_id==$o)|.contract_id'
}

# send_cef TOKEN URL CONTRACT_ID NAME JSON -> sets TID, or SEND_CODE on failure
send_cef() {
  local data; data="$(printf '%s' "$5" | base64 | tr -d '\n')"
  post_json "$2/api/admin/transfers" \
    "$(jq -n --arg c "$3" --arg n "$4" --arg d "$data" '{_func:"initiate_transfer",contract_id:$c,file_name:$n,file_data:$d}')" \
    "Authorization: Bearer $1"
  SEND_CODE="$CODE"; TID="$(printf '%s' "$RESP" | jq -r '.transfer_id // empty')"
}

# transfer_status TOKEN URL TID -> prints status
transfer_status() {
  admin "$2" "$1" transfers '{"_func":"list_transfers"}'
  printf '%s' "$RESP" | jq -r --arg t "$3" '.data[]|select(.transfer_id==$t)|.status'
}

wait_status() {   # wait_status TOKEN URL TID "Delivered|Received" -> 0 when reached
  local s
  s() { st="$(transfer_status "$1" "$2" "$3")"; [[ "$st" =~ ^($4)$ ]]; }
  wait_for s "$@"
}

expect() {   # expect LABEL CONDITION_EXIT_CODE
  if [ "$2" = "0" ]; then ok "$1"; else printf '    %s✘%s %s\n' "$_R" "$_N" "$1" >&2; FAILS=$((FAILS+1)); fi
}

step "Find the CEF-EVENTS contracts"
CEF_B="$(cef_contract "$TOKEN_A" "$NODE_A_URL" "$NODE_B_ID")"
CEF_A="$(cef_contract "$TOKEN_B" "$NODE_B_URL" "$NODE_A_ID")"
[ -n "$CEF_B" ] || die "Node A has no CEF-EVENTS for $NODE_B_ID (are the nodes Active partners? run 02 first)"
[ -n "$CEF_A" ] || die "Node B has no CEF-EVENTS for $NODE_A_ID"
ok "Node A -> Node B contract: $CEF_B"
ok "Node B -> Node A contract: $CEF_A"

step "Node A grants consent (two purposes) and Node B receives it"
GRANT="$(jq -nc --arg p "$PID" --arg f "$FID" --arg t "$(date -u +%FT%TZ)" '{cef_version:"1.0",events:[{
  event_id:("e-grant-"+$p),event_type:"CONSENT_GRANTED",event_time:$t,fiduciary_id:$f,principal_id:$p,
  consent_id:("c-"+$p),granted_at:$t,
  purposes:[{purpose_id:"loan_underwriting",status:"granted",data_categories:["income","pan"]},
            {purpose_id:"credit_marketing",status:"granted",data_categories:["email"]}]}]}')"
send_cef "$TOKEN_A" "$NODE_A_URL" "$CEF_B" "cef-grant-$RUN_ID.json" "$GRANT"
[ "$SEND_CODE" = "201" ] || [ "$SEND_CODE" = "200" ]; expect "grant accepted by Node A (HTTP $SEND_CODE)" $?
GRANT_TID="$TID"
wait_status "$TOKEN_A" "$NODE_A_URL" "$GRANT_TID" "Delivered|Failed"; expect "Node A status: $st" $([ "$st" = Delivered ] && echo 0 || echo 1)
wait_status "$TOKEN_B" "$NODE_B_URL" "$GRANT_TID" "Received"; expect "Node B status: $st" $([ "$st" = Received ] && echo 0 || echo 1)
admin "$NODE_B_URL" "$TOKEN_B" transfers "$(jq -n --arg t "$GRANT_TID" '{_func:"get_transfer_payload",transfer_id:$t}')"
printf '%s' "$RESP" | jq -r '.payload' | jq -e --arg p "$PID" '.events[0].principal_id==$p and (.events[0].purposes|length)==2' >/dev/null
expect "Node B holds the full event with both purposes" $?

step "Node A withdraws one purpose (full new state) and requests erasure"
WITHDRAW="$(jq -nc --arg p "$PID" --arg f "$FID" --arg t "$(date -u +%FT%TZ)" '{cef_version:"1.0",events:[
  {event_id:("e-wd-"+$p),event_type:"CONSENT_WITHDRAWN",event_time:$t,fiduciary_id:$f,principal_id:$p,
   consent_id:("c-"+$p),granted_at:$t,
   purposes:[{purpose_id:"loan_underwriting",status:"granted",data_categories:["income","pan"]},
             {purpose_id:"credit_marketing",status:"withdrawn",data_categories:["email"]}]},
  {event_id:("e-er-"+$p),event_type:"ERASURE_REQUESTED",event_time:$t,fiduciary_id:$f,principal_id:$p,
   request_id:("r-"+$p),trigger:"ErasureRequest",purpose_ids:["credit_marketing"],
   deadline_at:"2099-01-01T00:00:00Z"}]}')"
send_cef "$TOKEN_A" "$NODE_A_URL" "$CEF_B" "cef-withdraw-$RUN_ID.json" "$WITHDRAW"
WD_TID="$TID"
wait_status "$TOKEN_B" "$NODE_B_URL" "$WD_TID" "Received"; expect "Node B received the withdrawal and erasure request" $([ "$st" = Received ] && echo 0 || echo 1)

step "Node B confirms the erasure to Node A"
REPLY="$(jq -nc --arg p "$PID" --arg f "$FID" --arg t "$(date -u +%FT%TZ)" '{cef_version:"1.0",events:[
  {event_id:("e-cf-"+$p),event_type:"ERASURE_CONFIRMED",event_time:$t,fiduciary_id:$f,principal_id:$p,
   request_id:("r-"+$p),reply_status:"COMPLETED",records_affected_count:4,details:"Marketing records deleted",
   confirmed_by:"processor-ops",confirmed_at:$t}]}')"
send_cef "$TOKEN_B" "$NODE_B_URL" "$CEF_A" "cef-reply-$RUN_ID.json" "$REPLY"
wait_status "$TOKEN_A" "$NODE_A_URL" "$TID" "Received"; expect "Node A received the ERASURE_CONFIRMED reply" $([ "$st" = Received ] && echo 0 || echo 1)

step "Negative checks"
bad() {   # bad LABEL JSON : the transfer must end Failed on Node A and never reach Node B
  send_cef "$TOKEN_A" "$NODE_A_URL" "$CEF_B" "cef-bad-$RUN_ID-$1.json" "$2"
  if [ "$SEND_CODE" != "201" ] && [ "$SEND_CODE" != "200" ]; then ok "$1: refused at submission (HTTP $SEND_CODE)"; return; fi
  wait_status "$TOKEN_A" "$NODE_A_URL" "$TID" "Failed|Delivered"
  expect "$1: not delivered (Node A status: $st)" $([ "$st" = Failed ] && echo 0 || echo 1)
}
bad "missing-principal"  '{"cef_version":"1.0","events":[{"event_id":"x1","event_type":"CONSENT_GRANTED","event_time":"2026-01-01T00:00:00Z","fiduciary_id":"f"}]}'
bad "unknown-event-type" '{"cef_version":"1.0","events":[{"event_id":"x2","event_type":"SOMETHING_ELSE","event_time":"2026-01-01T00:00:00Z","fiduciary_id":"f","principal_id":"p"}]}'
bad "wrong-version"      '{"cef_version":"2.0","events":[{"event_id":"x3","event_type":"CONSENT_GRANTED","event_time":"2026-01-01T00:00:00Z","fiduciary_id":"f","principal_id":"p"}]}'
bad "empty-events"       '{"cef_version":"1.0","events":[]}'
bad "not-json"           'this is not json'

admin_raw() { post_json "$1/api/admin/$3" "$4" "Authorization: Bearer $2"; }
admin_raw "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$CEF_A" '{_func:"update_contract",contract_id:$c,name:"renamed"}')"
[ "$CODE" = "403" ]; expect "CEF-EVENTS cannot be edited (HTTP $CODE)" $?
admin_raw "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$CEF_A" '{_func:"deactivate_contract",contract_id:$c}')"
[ "$CODE" = "403" ]; expect "CEF-EVENTS cannot be suspended (HTTP $CODE)" $?

printf '\n'
if [ "$FAILS" -eq 0 ]; then printf '%sConsent channel checks passed.%s\n' "$_G" "$_N"; else die "$FAILS consent channel check(s) failed."; fi
