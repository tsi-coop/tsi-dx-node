# Security Hardening

Security controls built into TSI DX Node, and the deployment settings that make them effective. Use this as a checklist when standing up a node. The trust model these controls implement is described in the [Architecture](../design/architecture.md#3-trust-and-security-model).

## Deployment checklist

| Setting | Purpose | Required |
|---|---|---|
| `TSI_DX_NODE_BOOTSTRAP_TOKEN` | Authorises first-time node setup (`init.html`). **No built-in default**: unset = setup refused (`503`). Generate with `openssl rand -hex 32`. | Yes, for first setup |
| `TSI_DX_NODE_JWT_SECRET` | Signing key for admin session tokens: a unique random value of 32+ characters. There is **no built-in default**: outside `local`/`development`/`dev` the node refuses to start without it, and in those modes a random per-process key is used (sessions end on restart). Sample placeholder values are rejected. | Yes, in production |
| `TSI_DX_NODE_ENV` | `development` / `local` / `dev` omit the `Secure` cookie flag so plain-http testing works. Any other value (default `production`) sets it. | Recommended |
| `TSI_DX_NODE_P2P_SIGNATURES` | Leave unset. `optional` accepts unsigned peer calls and exists only for rolling upgrades between versions. | No |
| `TSI_DX_NODE_MAINTENANCE_SECONDS` | Interval of the retention purge and nonce clean-up (default `3600`). | No |
| Network placement | Keep the node's P2P port reachable only from partner nodes, and any `sync_responder_url` reachable only from the node. | Yes |

Generate secrets with `openssl rand -hex 32`.

**Setup token lifecycle.** `TSI_DX_NODE_BOOTSTRAP_TOKEN` is only needed while a node is being initialised. Set it, initialise the node (enter the token in the **Setup Token** field of `init.html`), then remove it from the environment and restart. With no token configured, first-time setup is refused outright (`503`), so an unattended node cannot be taken over through the setup endpoint. The token is checked before anything else: a wrong token is `401`, and only a correct token on an already-initialised node reaches the `409`. Never reuse the token across nodes or commit it; the `dev-node-*-setup-token` values in the sample `.env.node-*` files are for local testing only.

> `docker-compose.yml` passes `TSI_DX_NODE_JWT_SECRET` to the node, taking it from your `.env` (the older `TSI_PRIVACY_VAULT_JWT_SECRET` name is still read as a fallback). There is no compose default.

## Controls

### 1. First-time setup requires a setup token

`POST /api/admin/registeradmin` creates the node identity and the first administrator. Anyone able to reach an uninitialised node could otherwise claim it, so:

- The request must carry `setup_token` equal to `TSI_DX_NODE_BOOTSTRAP_TOKEN`, compared in constant time.
- There is no default: if the variable is not set on the server, setup returns `503` rather than being open.
- The token is checked before any database access, so a caller without it cannot learn whether the node is already initialised.
- The "already initialised?" check and the inserts run in one `SERIALIZABLE` transaction; if two setup requests race, the loser is aborted and gets `409`.
- Once an administrator exists, setup returns `409` regardless of the token. The variable can then be unset or rotated.

The setup page (`init.html`) has a **Setup Token** field for this value.

### 2. Console pages are gated server-side

The admin console pages (`dashboard`, `contracts`, `partners`, `transfers`, `apikeys`, `users`, `audit`, `settings`) are only served to a request that carries a valid session:

- `ConsoleAuthFilter` runs before the page is served and redirects to `/index.html` when there is no valid session.
- Login sets an `HttpOnly; SameSite=Strict` cookie (`console_session`, plus `Secure` outside development) carrying the admin token, so ordinary browser navigation can present it. Logout (`DELETE /api/admin/login`) expires it.
- This is in addition to, not instead of, API authentication: every `/api/admin/*` call is still authenticated on its own via the `Authorization: Bearer` header.
- Public pages are `index.html` (login), `init.html` (setup), `password_reset.html`, and `/tour/`.

### 3. Authentication precedes payload validation

For `/api/admin/*`, the token is verified before any request body is parsed or schema-validated, so an unauthenticated caller receives `401` and cannot map request schemas from validation errors. Only login, password reset and initial setup are reachable without a token, by design. `/api/client/dx` requires `X-API-Key` and `X-API-Secret` before any payload handling.

### 4. Peer handshake is limited to peer functions

Node-to-node calls carry the `X-DX-P2P-HANDSHAKE` header instead of an admin token. It is honoured only for the inbound peer functions on the route that serves each one:

| Route | Functions accepted with the handshake header |
|---|---|
| `/api/admin/partners` | `probe`, `receive_partnership_proposal`, `receive_termination_request`, `receive_termination_finalization` |
| `/api/admin/contracts` | `receive_contract_invitation`, `confirm_invitation`, `decline_invitation`, `notify_participant_suspended`, `notify_contract_suspended` |
| `/api/admin/transfers` | `receive_transfer_stream`, `receive_sync_request` |

Every other function, on any route, needs an admin token even when the header is present. The check covers both the `X-DX-FUNCTION` header and the body `_func`, because different handlers honour different ones. If you add a new peer-to-peer function, add it to `P2P_ALLOWED_FUNCS` in `InterceptingFilter`.

The header is a fixed protocol marker, not a secret: it only routes a request to this allow-list. What authenticates the peer is the signature described next.

### 5. Peer requests are signed

Every node-to-node request carries `X-DX-NODE-ID`, `X-DX-TARGET-NODE-ID`, `X-DX-TIMESTAMP`, `X-DX-REQUEST-ID` and `X-DX-SIGNATURE`: a signature, made with the sender's identity key, over `DX-P2P-SIG-V1`, the sender id, target id, function, timestamp, request id and the SHA-256 of the body. The receiver verifies it against the public key registered for that partner and refuses with `401` when:

- the request is unsigned (only `probe` and `receive_partnership_proposal`, which arrive before the sender is a known partner, may be unsigned; they only create `Pending` records an administrator must accept);
- the signer is not a registered partner, or the relationship is `Terminated`/`Inactive`;
- the signature does not verify, or the timestamp is more than 5 minutes off;
- the request id was already used (a captured request cannot be replayed);
- the target is another node;
- `sender_node_id` in the body names a node other than the signer.

This is message-level authentication, so it holds whatever sits in front of the node (a load balancer, a TLS-terminating proxy). The Jetty connector itself does not require client certificates.

### 6. The receiver enforces its own contract

A receiving node does not trust that a sender governed the data. Async transfers and sync requests are validated against the receiver's copy of the contract (schema, and that every anonymised field is in its masked/hashed/tokenised form) before anything is stored or forwarded, and refused with `400` otherwise. Data is not transformed a second time. Duplicate deliveries of a transfer already held are acknowledged, not re-stored.

### 7. No directory listings

The default servlet is configured with `dirAllowed=false`, so a directory without a welcome file returns an error instead of a file listing.

### 8. File names are confined to the storage directory

`file_name` comes from client applications and, on the receiving side, from partner nodes, and is used to build a path under the node's storage directory. It must be a single plain name: path separators (`/`, `\`), `..`, `:`, NUL and control characters are rejected with `400`, and the resolved path is checked to stay inside the storage directory before anything is read or written. The check (`SafeFilePath`) runs on the Client API, the console upload path, the receiver's inbound stream handler (before any sequence number or registry row is touched) and on every read of a stored file.

### 9. Test coverage

[`examples/scripts/06-negative-tests.sh`](../../examples/scripts/06-negative-tests.sh) exercises these controls, and the signature, replay, authorisation, enforcement and contract-lifecycle checks, against two running nodes. The scenario list is in the [scripts README](../../examples/scripts/README.md#negative-test-scenarios-06-negative-testssh).

## Reporting a vulnerability

See [SECURITY.md](../../SECURITY.md).
