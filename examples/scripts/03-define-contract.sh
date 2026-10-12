#!/usr/bin/env bash
# Step 3 - Data contract definition.
#
# The RECEIVER (Node B) authors the contract: schema (L1), PII rules (L2), and for sync
# contracts the internal responder URL and timeout. It then invites the sender (Node A), which
# accepts. After this the contract is Active on both nodes and Node A is an Active participant.
#
#   async  "Weekly Loan Applications"  - batch packages, PII hashed/masked      (payloads/async-contract-schema.json)
#   sync   "Loan Eligibility Check"    - request/response via a responder        (payloads/sync-contract-schema.json)
#
# Safe to re-run: existing contracts are found by name and reused.
#
# Requires: curl, jq. Run 01 and 02 first.
#
# Usage:
#   ./03-define-contract.sh            # both contracts
#   ./03-define-contract.sh async|sync
#
# Configuration:
#   SYNC_RESPONDER_URL   internal service Node B forwards sync requests to
#                        (default http://mock-responder:8099/eligibility - the compose mock)
#   SYNC_TIMEOUT_MS      per-call budget for sync contracts (default 10000)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

SYNC_RESPONDER_URL="${SYNC_RESPONDER_URL:-http://mock-responder:8099/eligibility}"
SYNC_TIMEOUT_MS="${SYNC_TIMEOUT_MS:-10000}"
PAYLOADS="$EXAMPLES_DIR/payloads"

TOKEN_A="$(login "$NODE_A_URL")" || exit 1; TOKEN_B="$(login "$NODE_B_URL")" || exit 1

contract_status() {  # url token contract_id
  admin "$1" "$2" contracts '{"_func":"list_contracts"}'
  printf '%s' "$RESP" | jq -r --arg c "$3" '.[]|select(.contract_id==$c)|.status' | head -n1
}

define() {   # kind name
  local kind="$1" name="$2" cid body
  step "Contract: $name [$kind]"

  # 1. Find or create on the receiver
  admin "$NODE_B_URL" "$TOKEN_B" contracts '{"_func":"list_contracts"}'
  cid="$(printf '%s' "$RESP" | jq -r --arg n "$name" '.[]|select(.name==$n)|.contract_id' | head -n1)"
  if [ -n "$cid" ]; then
    ok "Already exists on Node B ($cid)"
  else
    if [ "$kind" = sync ]; then
      body="$(jq -n --arg n "$name" --argjson s "$(cat "$PAYLOADS/sync-contract-schema.json")" \
              --arg url "$SYNC_RESPONDER_URL" --argjson t "$SYNC_TIMEOUT_MS" '{
        _func:"create_contract", name:$n, description:"Created by examples/scripts",
        interaction_type:"sync", schema_definition:$s,
        metadata:{format:"json", sync_responder_url:$url, sync_timeout_ms:$t,
                  governance_rules:{pii_anonymization:{mobile:"MASK"}}},
        pii_fields:["mobile"]}')"
    else
      body="$(jq -n --arg n "$name" --argjson s "$(cat "$PAYLOADS/async-contract-schema.json")" '{
        _func:"create_contract", name:$n, description:"Created by examples/scripts",
        interaction_type:"async", schema_definition:$s,
        metadata:{format:"json",
                  governance_rules:{pii_anonymization:{applicant_id:"HASH", mobile:"MASK"}}},
        retention_policy_days:30, pii_fields:["applicant_id","mobile"]}')"
    fi
    admin "$NODE_B_URL" "$TOKEN_B" contracts "$body"
    cid="$(printf '%s' "$RESP" | jq -r .contract_id)"
    ok "Created on Node B ($cid), status Draft"
  fi

  # 2. Invite the sender unless it is already a participant
  admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$cid" '{_func:"get_contract",contract_id:$c}')"
  if printf '%s' "$RESP" | jq -e --arg n "$NODE_A_ID" 'any(.participants[]?; .node_id==$n)' >/dev/null; then
    ok "$NODE_A_ID already invited"
  else
    admin "$NODE_B_URL" "$TOKEN_B" contracts "$(jq -n --arg c "$cid" --arg n "$NODE_A_ID" '{_func:"invite_node",contract_id:$c,node_id:$n}')"
    ok "Invited $NODE_A_ID"
  fi

  # 3. Sender accepts
  local st; st="$(contract_status "$NODE_A_URL" "$TOKEN_A" "$cid")" || exit 1
  [ -n "$st" ] || die "Node A has not received the invitation for $cid (is the partner handshake complete?)"
  if [ "$st" = "Active" ]; then
    ok "Already accepted on Node A"
  else
    admin "$NODE_A_URL" "$TOKEN_A" contracts "$(jq -n --arg c "$cid" '{_func:"accept_contract",contract_id:$c}')"
    ok "Node A accepted"
  fi

  # 4. Verify both sides
  [ "$(contract_status "$NODE_A_URL" "$TOKEN_A" "$cid")" = "Active" ] || die "Contract is not Active on Node A"
  [ "$(contract_status "$NODE_B_URL" "$TOKEN_B" "$cid")" = "Active" ] || die "Contract is not Active on Node B"
  ok "Active on both nodes"
  state_set "${kind}_contract_id" "$cid"
}

case "${1:-both}" in
  async) define async "Weekly Loan Applications" ;;
  sync)  define sync  "Loan Eligibility Check" ;;
  both)  define async "Weekly Loan Applications"; define sync "Loan Eligibility Check" ;;
  *) die "Usage: $0 [async|sync]" ;;
esac
