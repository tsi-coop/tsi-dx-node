# TSI DX Node: Open Source B2B Data Exchange Solution

TSI DX Node is an open-source solution designed for peer-to-peer data exchange among business partners. It eliminates the need for centralized intermediaries by allowing direct, secure, and governed data flows between independent nodes.

For a high-level functional overview and the rationale behind this architecture, read our [soft launch post](https://techadvisory.substack.com/p/tsi-dx-node-open-source-b2b-data).

## Installation

To begin your evaluation of the TSI DX Node, clone the repository to a local directory:

```bash
git clone https://github.com/tsi-coop/tsi-dx-node.git tsi-dx-node-eval
```
## Two Exchange Lanes

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

### 1. Prerequisites

- Docker with Docker Compose v2 (the node is built and run in containers; no local Java or Maven needed)
- `curl`, `jq`, `openssl` and `base64` on the host, for the example scripts
- Free host ports `8082`, `8083`, `8443`, `9443`, `5434` and `5435` (the two local nodes and their databases)

### 2. Start two nodes

From the repository root:

```bash
docker network create tsi-p2p-net      # once; ignore "already exists"

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-a --env-file .env.node-a up --build -d

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-b --env-file .env.node-b up --build -d
```

Always pass `--project-name` and `--env-file`; a plain `docker compose up` uses the default ports and collides with these. Node A is then on `http://localhost:8082` and Node B on `http://localhost:8083`. The first build takes a few minutes; both URLs should return `200` for `/index.html` when ready. Details: [Local Testing Guide](docs/guides/local-testing-guide.md) sections 1-4.

### 3. Run the exchange

Either run the [example scripts](examples/scripts/README.md), which take two fresh nodes through setup, partner handshake, a data contract, an async transfer and a sync call:

```bash
cd examples/scripts && ./run-all.sh
```

or follow the [**Local Testing Guide**](docs/guides/local-testing-guide.md) step by step through the console. The video tutorials below cover each stage in depth.

## Guided Tour

Explore the core capabilities of the TSI DX Node through this step-by-step technical journey. Each stage includes a video tutorial to guide you through the process.

| Step | Milestone | Description | Documentation & Demo |
|------|-----------|-------------|----------------------|
| 01 | **Node Bootstrap** | Initialization of independent node instances. Setting the immutable Node ID, configuring the public FQDN, and establishing the root administrative identity. | [Watch Video](https://youtu.be/kieEhDHei-Q) |
| 02 | **Partner Handshake** | Executing the bidirectional identity protocol. Exchanging public keys, verifying mTLS endpoints, and establishing the verified link between independent nodes. | [Watch Video](https://youtu.be/0G5NrmXAtXM) |
| 03 | **Data Contracts** | Defining governance boundaries. Implementing L1 structural validation and L2 PII anonymization (Hashing/Masking) to enforce the Digital Agreement at the source. | [Watch Video](https://youtu.be/iSkrnkcbZzY) |
| 04 | **Transfer Service** | Executing the 'Single Package' routing. Monitoring sequences, message timestamps, and forensic mirroring of the transmitted data payloads. | [Watch Video](https://youtu.be/5Lu0wGrjoIM) |
| 05 | **API Integration** | Bridging internal systems. Registering applications (CRM/ERP), generating Client API credentials, and restricting access to specific authorized data contracts. | [Watch Video](https://youtu.be/MNuQCFofpdc) |

## Documentation

| Document | Covers |
|----------|--------|
| [Architecture](docs/design/architecture.md) | The design reference: trust model, receiver-authored contracts, governance, async and sync lanes, data model, design decisions, limits |
| [Local Testing Guide](docs/guides/local-testing-guide.md) | Two-node setup on one machine; async (§10) and sync (§11) walk-throughs |
| [Asynchronous Integration Guide](docs/guides/asynchronous-integration-guide.md) | Submitting and tracking batch transfers: Client API, statuses, failures, retention |
| [Synchronous Integration Guide](docs/guides/synchronous-integration-guide.md) | Real-time calls: contract setup, responder requirements, Client API, idempotency, errors |
| [Security Hardening Guide](docs/guides/security-hardening-guide.md) | Setup token, JWT secret, peer signatures, deployment checklist |
| [Changelog](CHANGELOG.md) | What changed in each release, with upgrade notes |
| [Example Scripts](examples/scripts/README.md) | Runnable scripts for node setup, partner handshake, contracts, async transfer, sync call, 80 negative test scenarios, teardown |

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
