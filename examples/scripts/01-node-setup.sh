#!/usr/bin/env bash
# Step 1 - Node setup: establish the node identity and first administrator on each node.
#
# Calls POST /api/admin/registeradmin (guarded by the node's TSI_DX_NODE_BOOTSTRAP_TOKEN),
# then logs in to prove the credentials work. Safe to re-run: an already-initialised node
# answers 409 and is treated as done.
#
# Requires: curl, jq, openssl.
#
# Usage:
#   ./01-node-setup.sh            # both nodes
#   ./01-node-setup.sh a|b        # one node
#
# Configuration (environment, defaults in lib/common.sh):
#   NODE_A_URL / NODE_B_URL      http://localhost:8082 / :8083
#   NODE_A_ID / NODE_B_ID        immutable node IDs
#   NODE_A_HOST / NODE_B_HOST    FQDN each node advertises to partners
#   SETUP_TOKEN_A / SETUP_TOKEN_B  must equal each node's TSI_DX_NODE_BOOTSTRAP_TOKEN
#   ADMIN_EMAIL / ADMIN_PASSWORD   first administrator
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

setup_node() {
  local label="$1" url="$2" node_id="$3" host="$4" token="$5"
  step "Node ${label^^} ($url)"
  post_json "$url/api/admin/registeradmin" "$(jq -n \
      --arg id "$node_id" --arg fqdn "$host" --argjson port "$P2P_PORT" \
      --arg u "$ADMIN_USERNAME" --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" --arg t "$token" \
      '{node_id:$id,fqdn:$fqdn,network_port:$port,username:$u,email:$e,password:$p,confirm:$p,setup_token:$t}')"
  case "$CODE" in
    201) ok "Initialised node '$node_id' with administrator $ADMIN_EMAIL" ;;
    409) ok "Already initialised - skipping" ;;
    401) die "Setup token rejected. Set SETUP_TOKEN_${label^^} to the node's TSI_DX_NODE_BOOTSTRAP_TOKEN." ;;
    503) die "Node has no TSI_DX_NODE_BOOTSTRAP_TOKEN configured, so setup is disabled." ;;
    *)   die "Setup failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .' 2>/dev/null)" ;;
  esac
  local jwt; jwt="$(login "$url")" || exit 1
  ok "Login succeeded"
  admin "$url" "$jwt" node '{"_func":"get_node_config"}'
  info "node_id=$(printf '%s' "$RESP" | jq -r '.node_id // .data.node_id // empty') fqdn=$(printf '%s' "$RESP" | jq -r '.fqdn // .data.fqdn // empty')"
}

WHICH="${1:-both}"
case "$WHICH" in
  a|A|both) setup_node a "$NODE_A_URL" "$NODE_A_ID" "$NODE_A_HOST" "$SETUP_TOKEN_A" ;;
esac
case "$WHICH" in
  b|B|both) setup_node b "$NODE_B_URL" "$NODE_B_ID" "$NODE_B_HOST" "$SETUP_TOKEN_B" ;;
esac
step "Done"
