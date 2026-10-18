# TSI DX Node

**A peer-to-peer node for governed data exchange between organisations.**

TSI DX Node is open source. It eliminates the need for centralized intermediaries by allowing direct, secure, and governed data flows between independent nodes. Every exchange runs under a contract the receiver defines and both ends enforce.

For a high-level functional overview and the rationale behind this architecture, read our [soft launch post](https://techadvisory.substack.com/p/tsi-dx-node-open-source-b2b-data).

## Why TSI DX Node

When two organisations exchange data (a lender and a loan service provider, a bank and a fintech, a clinic and a lab) the data usually moves through a shared platform, a bespoke API or a file drop, and nobody can answer afterwards: what exactly was sent, in what form, to whom, under what agreement, and was it allowed?

With TSI DX Node each organisation runs its own node. The two nodes agree a **data contract**, which the receiver writes: what fields are accepted and which personal data must be masked or hashed before it leaves. Both nodes enforce it, and both keep the evidence. Nothing sits in the middle, and your data stays on your own infrastructure.

The exchange can also be **consent aware**. Consent travels on its own channel beside the data: the sender shares each person's consent, any change or withdrawal, and any erasure request, and the receiver respects them and confirms back. Everyone in the chain works from the same record of what the person agreed to.

## Key Features

- **Contracts the receiver defines.** The organisation that receives the data states the schema and the anonymisation rules. Senders are invited to take part and do not write the terms.
- **Enforced at both ends.** The sender validates and anonymises at source, so raw personal data does not leave. The receiver checks again against its own copy of the contract and never trusts the sender's word.
- **Batch and real-time.** Push governed packages for loan files and reconciliations, or make governed request/response calls for eligibility, KYC and OTP checks.
- **Consent and erasure travel with the relationship.** A built-in channel carries consent, consent changes and erasure requests, and the confirmations back, in an open JSON format, separate from the data. See [Consent Exchange Format](docs/guides/consent-exchange-format.md).
- **Signed, replay-protected messages** between nodes, using identity keys each node already holds.
- **Reliable delivery.** Retry with backoff, duplicate suppression, ordered sequence numbers and a configurable retention period for stored payloads.
- **Evidence you can stand behind.** An immutable audit trail and a transfer log on both nodes, with the governed payload inspectable.

In short: governed, auditable exchange between organisations, without an intermediary.

## Functional Walkthrough

Setting up two nodes, the partner handshake, a data contract, async and sync exchange, the consent channel, and the audit trail.

[Watch the functional walkthrough](https://youtu.be/dEHe4t-Cb-E)

## Quick Start

You need Docker with Docker Compose v2, and a terminal. The scripted route below takes two fresh nodes through setup, partner handshake, a data contract, an async transfer, a sync call and the consent channel in a few minutes.

1. Clone the repository:
   ```bash
   git clone https://github.com/tsi-coop/tsi-dx-node.git tsi-dx-node-eval
   cd tsi-dx-node-eval
   ```
2. Start two nodes (details, ports and the setup token are in [Getting Started](#getting-started) below):
   ```bash
   docker network create tsi-p2p-net      # once; ignore "already exists"
   docker compose -f docker-compose.yml -f docker-compose.p2p.yml --project-name node-a --env-file .env.node-a up --build -d
   docker compose -f docker-compose.yml -f docker-compose.p2p.yml --project-name node-b --env-file .env.node-b up --build -d
   ```
3. Run the example scripts (needs `curl`, `jq`, `openssl` and `base64`):
   ```bash
   cd examples/scripts && ./run-all.sh
   ```
4. Open Node A at <http://localhost:8082> and Node B at <http://localhost:8083>, sign in as `admin@example.org` with the example password from the scripts README, and look at **Partner Nodes**, **Data Contracts**, **Transfer Logs** and **Consent Channel**.

## Developer Guides

New here? Work down this table in order.

| Stage | I want to... | Go to |
|---|---|---|
| **1. Install** | Start two nodes on one machine and walk through the console | [Local Testing Guide](docs/guides/local-testing-guide.md) |
| | Run the whole exchange from scripts | [Example scripts](examples/scripts/README.md) |
| **2. Understand** | See how it fits together and why | [Architecture](docs/design/architecture.md) |
| | Choose between batch and real-time | [Two Exchange Lanes](#two-exchange-lanes) |
| **3. Integrate** | Send governed packages from my application | [Asynchronous Integration Guide](docs/guides/asynchronous-integration-guide.md) |
| | Make real-time governed calls | [Synchronous Integration Guide](docs/guides/synchronous-integration-guide.md) |
| **4. Share consent** | Send consent, withdrawals and erasure requests, and act on them | [Consent and Erasure Guide](docs/guides/consent-and-erasure-guide.md) |
| | Build to the consent format, or map it from a CMS | [CEF spec](docs/guides/consent-exchange-format.md), [CEF to CMS Mapping](docs/guides/cef-cms-mapping.md) |
| **5. Production** | Set the setup token and JWT secret, and review the deployment checklist | [Security Hardening Guide](docs/guides/security-hardening-guide.md) |
| **Reference** | See what changed and how to upgrade | [Changelog](CHANGELOG.md) |

## Two Exchange Lanes

Every exchange is either batch or real time. Choose per contract.

Every exchange runs under a receiver-authored data contract with the same mTLS transport, L1 structural validation, L2 PII anonymization and immutable audit trail. What differs is the delivery lane, chosen per contract:

| | Async lane (batch) | Sync lane (real-time) |
|---|---|---|
| Contract `interaction_type` | `async` | `sync` |
| Pattern | Push a governed package; track by transfer ID | Request in, governed response out, on one held connection |
| Replay protection | Sequence number + message timestamp | Single-use nonce |
| Evidence | Transfer log + forensic mirror on both nodes | Per-call sync audit log on both nodes |
| Use for | Loan files, repayments, reconciliations, bulk PII | Eligibility, KYC validation, OTP, balance, credit decision |

The real-time lane is synchronous request/response between two nodes: the calling application invokes `execute_sync_request` on its own node, the node governs the payload, calls the partner node, which forwards it to an internal responder service and returns a governed response - all within a per-contract timeout (default 10 s). It includes a circuit breaker per partner and is not a streaming or pub/sub channel. See the [Architecture](docs/design/architecture.md) for the design, and the [Synchronous](docs/guides/synchronous-integration-guide.md) and [Asynchronous](docs/guides/asynchronous-integration-guide.md) integration guides for the API, error behaviour and limits of each.

## Getting Started

The Quick Start above in full: prerequisites, the setup token, and what each command does.

### 1. Prerequisites

- Docker with Docker Compose v2 (the node is built and run in containers; no local Java or Maven needed)
- `curl`, `jq`, `openssl` and `base64` on the host, for the example scripts
- Free host ports `8082`, `8083`, `8443`, `9443`, `5434` and `5435` (the two local nodes and their databases)

### 2. Set the setup token

First-time node setup (creating the node identity and the first administrator) is refused unless the request carries the value of `TSI_DX_NODE_BOOTSTRAP_TOKEN`. There is no built-in default. The repository ships development values in `.env.node-a` and `.env.node-b` (`dev-node-a-setup-token`, `dev-node-b-setup-token`), which is what the example scripts use, so a local trial needs no change.

For any node beyond a local trial, generate a different token per node and keep it out of version control. Each node reads its own `--env-file`:

```bash
sed -i "s/^TSI_DX_NODE_BOOTSTRAP_TOKEN=.*/TSI_DX_NODE_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)/" .env.node-a
sed -i "s/^TSI_DX_NODE_BOOTSTRAP_TOKEN=.*/TSI_DX_NODE_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)/" .env.node-b
# the example scripts must then be told the new values:
export SETUP_TOKEN_A=<value from .env.node-a> SETUP_TOKEN_B=<value from .env.node-b>
```

(For a single node started with a plain `docker compose up`, put the line in `.env` instead.) You enter that value in the **Setup Token** field of `/init.html` when you initialise the node, or pass it as `setup_token` to `registeradmin`. Once the node is initialised the token is no longer needed and can be removed from the environment; setup is then refused until it is set again. See the [Security Hardening Guide](docs/guides/security-hardening-guide.md).

### 3. Start two nodes

From the repository root:

```bash
docker network create tsi-p2p-net      # once; ignore "already exists"

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-a --env-file .env.node-a up --build -d

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-b --env-file .env.node-b up --build -d
```

Always pass `--project-name` and `--env-file`; a plain `docker compose up` uses the default ports and collides with these. Node A is then on `http://localhost:8082` and Node B on `http://localhost:8083`. The first build takes a few minutes; both URLs should return `200` for `/index.html` when ready. Details: [Local Testing Guide](docs/guides/local-testing-guide.md) sections 1-4.

### 4. Run the exchange

Either run the [example scripts](examples/scripts/README.md), which take two fresh nodes through setup, partner handshake, a data contract, an async transfer and a sync call:

```bash
cd examples/scripts && ./run-all.sh
```

or follow the [**Local Testing Guide**](docs/guides/local-testing-guide.md) step by step through the console (use the setup token from step 2 on the setup page).

## Use Cases

Real-world scenarios showing how TSI DX Node solves data exchange challenges across industries.

| Use Case | Description |
|----------|-------------|
| [LSP-Lender Data Exchange](usecases/lsp-bank-data-exchange.md) | How a loan service provider (LSP) and a bank use TSI DX Node to govern origination and servicing data across the loan lifecycle - lead intake, application, underwriting, booking, disbursement, and repayment. |

## Security

Set `TSI_DX_NODE_BOOTSTRAP_TOKEN` and a unique `TSI_DX_NODE_JWT_SECRET` before exposing a node; first-time setup is refused without the token. See [Security Hardening Guide](docs/guides/security-hardening-guide.md) and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License & Contributions

This project is fully open-source and distributed under the **Apache 2.0 License**. You are completely free to fork, modify, and customize the codebase to fit your specific technical or enterprise needs without any restriction.

### Contributing Back to the Main Project
If you have built an optimization, bug fix, or feature extension that you believe would add value to the core platform, we would love to review it. To ensure the main repository remains highly stable and securely managed, direct commits to the `main` branch are restricted.

If you wish to give back your changes to the project, please follow this process:

* **Email the Repository Owner:** Send a brief summary of your modifications and a link to your code branch directly to **admin@tsicoop.org**.

Every contribution is manually evaluated for architectural alignment, readability, and long-term maintenance impact before integration. Thank you for respecting this workflow and helping us maintain a clean, resilient core!
