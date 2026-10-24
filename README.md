<p align="center">
  <img src="https://raw.githubusercontent.com/gnomon-system/docs/main/assets/gnomonsystem-github-preview.png" alt="GnomonSystem — verifiable temporal infrastructure" width="100%">
</p>

<p align="center">
  <a href="https://gnomonsystem.cn/en/index.html"><img alt="Website" src="https://img.shields.io/badge/Website-gnomonsystem.cn-8d62e8?style=flat-square"></a>
  <a href="https://github.com/gnomon-system/docs"><img alt="Theory and documentation" src="https://img.shields.io/badge/Theory%20%26%20Docs-v4.4-7d5cff?style=flat-square"></a>
  <a href="https://forum.gnomonsystem.com/"><img alt="Forum" src="https://img.shields.io/badge/Forum-GnomonSystem-AD7AFF?style=flat-square"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/Specs-CC%20BY%204.0-ff8ed8?style=flat-square"></a>
</p>

# GnomonSystem Protocols

### Verifiable temporal infrastructure, from trusted time to reviewable events

GnomonSystem is the operating system for digital facts: it makes critical events independently verifiable—when they happened, who performed them, and whether they changed—without trusting a central authority. These versioned specifications define the protocol layers behind trusted time roots, event anchoring, subject credentials, verification, and tracing.

## Protocol map

| Layer | English specification | 中文规范 | Forum release | Purpose |
|---|---|---|---|---|
| **P1 · Prime** | [RFC-P1-001](en/RFC-P1-001_GnomonSystem_Prime_Protocol_v4.4.md) | [RFC-P1-001 天枢](zh/RFC-P1-001_日冕系统_天枢_协议_v4.4.md) | [EN](https://forum.gnomonsystem.com/t/rfc-p1-001-gnomonsystem-prime-protocol-v4-4/17) · [中文](https://forum.gnomonsystem.com/t/rfc-p1-001-v4-4/23) | Trusted physical-time root, node identity, and issuance authorization. |
| **P2 · Polaris** | [RFC-P2-001](en/RFC-P2-001_GnomonSystem_Polaris_Protocol_v4.4.md) | [RFC-P2-001 天璇](zh/RFC-P2-001_日冕系统_天璇_协议_v4.4.md) | [EN](https://forum.gnomonsystem.com/t/rfc-p2-001-gnomonsystem-polaris-protocol-v4-4/18) · [中文](https://forum.gnomonsystem.com/t/rfc-p2-001-v4-4/24) | Digest-based event anchors, existence and ordering proof, chain verification, and tracing. |
| **P3 · Iris** | [RFC-P3-001](en/RFC-P3-001_GnomonSystem_Iris_Protocol_v4.4.md) | [RFC-P3-001 天玑](zh/RFC-P3-001_日冕系统_天玑_协议_v4.4.md) | [EN](https://forum.gnomonsystem.com/t/rfc-p3-001-gnomonsystem-iris-protocol-v4-4/19) · [中文](https://forum.gnomonsystem.com/t/rfc-p3-001-v4-4/25) | Subject claims, entity fingerprints, attribute credentials, and scoped disclosure. |

The public website gives developers an overview of **Prime** and **Polaris** as the core product layers. This repository publishes the complete P1–P3 specification set; each file follows the corresponding English or Chinese forum release, with forum continuation markers removed when posts are assembled into one document.

## Design goals

- Anchor event digests rather than expose business payloads to nodes or public networks.
- Make event existence, temporal order, and causal relationships independently verifiable.
- Let integrators use standard APIs and SDKs for verification, tracing, reconciliation, and coordination.
- Preserve explicit layer boundaries and versioned, reviewable protocol semantics.

## Project links

- [English website](https://gnomonsystem.cn/en/index.html)
- [Theory documents](https://github.com/gnomon-system/docs)
- [Forum protocol releases](https://forum.gnomonsystem.com/c/protocols/rfcs-schemas/9)
- [X](https://x.com/gnomonsystem) · [Discord](https://discord.gg/nqDS9y2eY)

## Contributing

Protocol changes should be proposed with a specific RFC identifier, section, rationale, and compatibility impact. Published v4.4 files are preserved as a versioned baseline; substantive changes should be introduced as a reviewed new version or change proposal.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the submission format.

## License

The specification text is licensed under [Creative Commons Attribution 4.0 International](LICENSE). Retain attribution and the license link and indicate modifications. GnomonSystem names, logos, and other trademarks are not included in this copyright license.

---

### 中文简介

本仓库收录 GnomonSystem v4.4 的 P1–P3 协议中英文规范：天枢/Prime 定义可信时间根与签发边界；天璇/Polaris 定义事件锚定、证明和追踪；天玑/Iris 定义主体与属性凭证。业务原文不经节点流转，节点以摘要和密码学凭证完成独立验证。
