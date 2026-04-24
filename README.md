# TSI DX Node: Open Source B2B Data Exchange Solution

TSI DX Node is an open-source, decentralized solution designed for peer-to-peer data exchange among business partners. It eliminates the need for centralized intermediaries by allowing direct, secure, and governed data flows between independent nodes.

For a high-level functional overview and the rationale behind this architecture, read our [soft launch post](#).

---

## Installation

To begin your evaluation of the TSI DX Node, clone the repository to a local directory:

```bash
git clone https://github.com/tsi-coop/tsi-dx-node.git tsi-dx-node-eval
```

---

## Getting Started

To set up your environment and run your first peer-to-peer exchange, please follow the detailed instructions in our **Local Testing Guide**. This guide covers the prerequisites and configuration steps necessary to simulate a multi-node network on your machine.

---

## Technical Journey: Guided Tour

Explore the core capabilities of the TSI DX Node through this step-by-step technical journey. Each stage includes a deep-dive video tutorial to guide you through the process.

| Step | Milestone | Description | Documentation & Demo |
|------|-----------|-------------|----------------------|
| 01 | **Node Bootstrap** | Initialization of independent node instances. Setting the immutable Node ID, configuring the public FQDN, and establishing the root administrative identity. | [Watch Video](#) |
| 02 | **Partner Handshake** | Executing the bidirectional identity protocol. Exchanging public keys, verifying mTLS endpoints, and establishing the verified link between independent nodes. | [Watch Video](#) |
| 03 | **Data Contracts** | Defining governance boundaries. Implementing L1 structural validation and L2 PII anonymization (Hashing/Masking) to enforce the Digital Agreement at the source. | [Watch Video](#) |
| 04 | **Transfer Service** | Executing the 'Single Package' routing. Monitoring sequences, message timestamps, and forensic mirroring of the transmitted data payloads. | [Watch Video](#) |
| 05 | **API Integration** | Bridging internal systems. Registering applications (CRM/ERP), generating Client API credentials, and restricting access to specific authorized data contracts. | [Watch Video](#) |

---

## License

This project is released under the [Apache 2 License](https://www.apache.org/licenses/LICENSE-2.0).