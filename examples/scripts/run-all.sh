#!/usr/bin/env bash
# Runs the whole example end to end against two running nodes: setup, identity + handshake,
# both contracts, one async transfer, one sync call, then the negative tests. Stops at the first failure.
#
# Prerequisite: both nodes up as described in docs/guides/local-testing-guide.md section 4
# (docker-compose.p2p.yml, .env.node-a / .env.node-b). Then:
#
#   ./run-all.sh
#
# Override endpoints/identities with the variables listed in lib/common.sh.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
for s in ./01-node-setup.sh ./02-identity-and-partners.sh ./03-define-contract.sh \
         ./04-async-transfer.sh ./05-sync-call.sh "./05-sync-call.sh --invalid" ./06-negative-tests.sh ./07-consent-exchange.sh; do
  $s || { echo "FAILED: $s" >&2; exit 1; }
done
printf '\n\033[32mAll example steps passed.\033[0m\n'
