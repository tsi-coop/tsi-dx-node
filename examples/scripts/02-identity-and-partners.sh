#!/usr/bin/env bash
# Step 2 - Node identity and partner handshake.
#
#   1. Generates a private key and self-signed certificate per node (CN = the node's hostname).
#   2. Activates each certificate on its node        (import_node_certificate).
#   3. Registers each node as a partner of the other (create_partner).
#   4. Runs the handshake from Node A                (accept_partnership) - the nodes exchange
#      public keys over HTTPS and both sides move to Active.
#
# Keys and certificates are kept in STATE_DIR and reused on re-run. Self-signed certificates
# are for evaluation; use your own CA in real deployments.
#
# Requires: curl, jq, openssl. Run 01-node-setup.sh first.
#
# Usage:  ./02-identity-and-partners.sh
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

make_identity() {   # label host
  local label="$1" host="$2" key="$STATE_DIR/node_$1.key" crt="$STATE_DIR/node_$1.pem"
  if [ -s "$key" ] && [ -s "$crt" ]; then ok "Reusing identity for Node ${label^^} ($host)"; return; fi
  # The backend requires PKCS#8 private keys.
  openssl genrsa -out "$STATE_DIR/node_$label.raw" 2048 2>/dev/null || die "openssl key generation failed"
  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "$STATE_DIR/node_$label.raw" -out "$key"
  rm -f "$STATE_DIR/node_$label.raw"
  openssl req -new -x509 -key "$key" -out "$crt" -days 365 -subj "/CN=$host/O=TSI DX Node Example" \
    || die "openssl certificate generation failed"
  ok "Generated key and certificate for Node ${label^^} (CN=$host)"
}

activate() {        # label url token
  admin "$2" "$3" node "$(jq -n --rawfile c "$STATE_DIR/node_$1.pem" --rawfile k "$STATE_DIR/node_$1.key" \
    '{_func:"import_node_certificate",certificate_pem:$c,private_key_pem:$k}')"
  ok "Node ${1^^}: $(printf '%s' "$RESP" | jq -r .message)"
}

register_partner() { # url token partner_node_id partner_host partner_cert_label -> prints partner_id
  admin "$1" "$2" partners "$(jq -n --arg id "$3" --arg f "$4:$P2P_PORT" --rawfile k "$STATE_DIR/node_$5.pem" \
    '{_func:"create_partner",name:$id,node_id:$id,fqdn:$f,public_key_pem:$k}')"
  printf '%s' "$RESP" | jq -r .partner_id
}

step "Generate identities"
make_identity a "$NODE_A_HOST"
make_identity b "$NODE_B_HOST"

TOKEN_A="$(login "$NODE_A_URL")" || exit 1; TOKEN_B="$(login "$NODE_B_URL")" || exit 1

step "Activate certificates"
activate a "$NODE_A_URL" "$TOKEN_A"
activate b "$NODE_B_URL" "$TOKEN_B"

step "Register partners (each node registers the other's public key)"
PARTNER_B_ON_A="$(register_partner "$NODE_A_URL" "$TOKEN_A" "$NODE_B_ID" "$NODE_B_HOST" b)" || exit 1
PARTNER_A_ON_B="$(register_partner "$NODE_B_URL" "$TOKEN_B" "$NODE_A_ID" "$NODE_A_HOST" a)" || exit 1
ok "Node A knows $NODE_B_ID; Node B knows $NODE_A_ID (status Pending)"

step "Handshake (Node A -> Node B)"
post_json "$NODE_A_URL/api/admin/partners" "$(jq -n --arg p "$PARTNER_B_ON_A" '{_func:"accept_partnership",partner_id:$p}')" \
  "Authorization: Bearer $TOKEN_A"
if [ "$CODE" != "200" ]; then
  die "Handshake failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .' 2>/dev/null)
    Check that each node can resolve the other by '$NODE_A_HOST' / '$NODE_B_HOST' and that both
    names are covered by the transport certificate (see docs/guides/local-testing-guide.md section 7)."
fi
ok "$(printf '%s' "$RESP" | jq -r '.message')"

step "Verify partner status"
partner_active() {   # url token node_id
  admin "$1" "$2" partners '{"_func":"list_partners"}'
  [ "$(printf '%s' "$RESP" | jq -r --arg n "$3" '.[]|select(.node_id==$n)|.status')" = "Active" ]
}
wait_for partner_active "$NODE_A_URL" "$TOKEN_A" "$NODE_B_ID" || die "Node A never saw $NODE_B_ID as Active"
wait_for partner_active "$NODE_B_URL" "$TOKEN_B" "$NODE_A_ID" || die "Node B never saw $NODE_A_ID as Active"
ok "Both partner records are Active"
state_set partner_b_on_a "$PARTNER_B_ON_A"; state_set partner_a_on_b "$PARTNER_A_ON_B"
