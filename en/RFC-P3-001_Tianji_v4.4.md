# RFC-P3-001 — **GnomonSystem** (Iris) Protocol

**GnomonSystem Protocol Baseline v4.4**

**V4.4 · 2026-09-11 · GNOMON BASELINE V4.4**  

---

## Abstract

This document defines the P3 layer of GnomonSystem: the Iris Protocol.

Iris addresses one core question: **What is a subject, where does it come from, and how can it be proved trustworthy?**

The theoretical basis of Iris is that a subject does not exist a priori; it emerges from verifiable event history.
The protocol follows this principle: ClaimAnchor does not “create” a subject, but “anchors” the relationship between the subject and its verifiable action history.

Core design:

- **EntityFingerprint:** Cryptographic identity for a subject, derived one-way from real identity material and irreversible; supports multiple subject types (natural persons, legal entities, AI Agents, and devices).
- **ClaimAnchor:** Cryptographic anchor for a subject's attribute claim, based on EEA timing and carrying dual signatures (the subject's awareness and the institution's endorsement).
- **AttributeType system:** Hierarchical attribute-type encoding covering everything from basic KYC to AI capability claims.
- **Endorsement trust chain:** Tree-shaped L1 → L2 → L3 trust structure; domain authorities endorse claims within their respective scopes.
- **WPO (observation window):** A minimal-disclosure mechanism in which the verifier sees only the required subset of attributes.
- **DerivedFingerprint:** Prevents cross-context correlation by using a different identifier for the same subject in different contexts.

---

## Contents

Terms and notation

Formal subject model
2.1 Agency and Subject
2.2 Type A subjects (a priori) and Type B subjects (derived)
2.3 Subjects are not created

EntityFingerprint specification
3.1 Calculation by subject type
3.2 Natural person (resident identity card)
3.3 Natural person (Hong Kong, Macao, Taiwan, or foreign national)
3.4 Legal entity (Unified Social Credit Code)
3.5 AI Agent
3.6 Device
3.7 Normalization requirements (MUST)

ClaimAnchor data structure
4.1 Field definition (504 B)
4.2 SubjectSignature (189-byte signing input)
4.3 IrisSignature (253-byte signing input)
4.4 Semantics of nested signatures
4.5 Field-construction order

AttributeType system
5.1 Encoding rules
5.2 KYC types (personal identity)
5.3 KYB types (legal-entity identity)
5.4 Qualification types (licenses · professional practice)
5.5 Internal organizational types (roles · permissions)
5.6 AI Agent types
5.7 Privacy-enhanced types (yes/no)
5.8 Custom types

Endorser trust chain
6.1 IssuerCertificate
6.2 Trust-chain levels (L1 → L2 → L3)
6.3 `allowed_attribute_types` constraints
6.4 Trust-chain verification algorithm (pseudocode)

ClaimAnchor lifecycle
7.1 State machine

**V4.1 security revision: issuance preconditions**

Before issuing a ClaimAnchor, all of the following preconditions MUST be met. Violation of any one item → reject issuance:

1. **Uniqueness constraint (P3-F-15):** If an Active ClaimAnchor already exists for the same EntityFP and AttributeType, another Active ClaimAnchor MUST NOT be issued. If the old Claim is in Revoked / Expired / Deregistered / Terminated state, reissuance is allowed (treated as a new Potential → Active transition).
2. **Pre-issuance state check (P3-F-32):** The current ClaimAnchor state MUST be checked at issuance. If it is Grace / Expired / Revoked / Deregistered / Terminated, issuance is not allowed directly. The subject MUST first follow the new Potential → Active flow.
3. **Issuer authorization check (P3-SEC-02):** The issuer MUST be in the trusted Issuer ACL, and its `OpCert.allowed_ops` MUST include the ClaimAnchor's AttributeType.

**Historical anchors are unaffected:** ClaimAnchors issued before the revision remain valid. ACL changes do not retroactively affect existing ClaimAnchors (P-004: the trust chain is irreversible).

7.2 Version chain (PreviousClaimAnchor)
7.3 Revocation rules
7.4 Cascade revocation (AI Agent scenarios)

Privacy-protection mechanisms
8.1 Hash semantic isolation
8.2 WPO (Windowed Proof Observation)
8.3 DerivedFingerprint
8.4 Reserved ZKP interface

Verification specification
9.1 Full ClaimAnchor verification algorithm (pseudocode)
9.2 Time-cut verification
9.3 Verification output format

Protocol messages (Protobuf)

Security considerations

Test vectors

Error and warning codes

Version history

---

## 1. Terms and notation

`H(·)` — SM3 hash function  
`Sign(sk, m)` — SM2 signature  
`Verify(pk, m, σ)` — SM2 verification  
`∥` — byte-string concatenation

`EntityFingerprint` — cryptographic identity of a subject, 32 B, `SM3(identity material)`  
`ClaimAnchor` — cryptographic anchor for a subject's attribute claim, 504 B  
`AttributeType` — attribute-type code, `uint16`  
`AttributeHash` — SM3 hash of attribute content, 32 B; plaintext is not stored  
`ValidUntil` — ClaimAnchor validity period, `uint64` TI value; `0` = never expires

`IssuerFingerprint` — endorser fingerprint, `SM3(institution SM2 public key)`, 32 B  
`IrisSignature` — endorser's signature on a ClaimAnchor, 64 B  
`SubjectSignature` — subject's signature on its own claim, 64 B

`WPO` — Windowed Proof Observation  
`DerivedFP` — DerivedFingerprint; context-specific correlation protection

**Type A subject:** an a priori subject (person, organization, or device) that exists before the protocol.  
**Type B subject:** a derived subject (AI Agent or temporary proxy) that comes into existence under specific conditions.

`domain_tag` (Iris): `b"Iris.Claim.v1"` (13 bytes)

---

## 2. Formal subject model

### 2.1 Agency and Subject

**Agency:** The smallest causal unit capable of causing a verifiable event.

$$\text{Agency}(a) \iff \exists E \in \mathcal{E},\ \text{Cause}(a, E)$$

**Subject:** A stable expression of an Agency within a particular observation window, defined by the four-tuple:

$$\text{Subject}(a, W) = (f_a,\ \mathcal{C}_a,\ \mathcal{R}_a,\ \mathcal{P}_a)$$

- `$f_a$`: EntityFingerprint, the subject's cryptographic identifier.
- `$\mathcal{C}_a$`: capability set (proved by ClaimAnchor).
- `$\mathcal{R}_a$`: responsibility set (derived from event history).
- `$\mathcal{P}_a$`: verifiable-attribute set.
- `$W = [t_s, t_e]$`: observation time window (TI range).

**A subject is structural semantics of an event:**

```text
Event E contains SemanticAnchor
SemanticAnchor.P3_ref → ClaimAnchor.AnchorID → EntityFingerprint
```

This reference chain cryptographically binds “the event occurred” and “who initiated the event.”
A subject is not an externally attached label; it emerges from the causal relationships of events.

### 2.2 Type A and Type B subjects

**Type A subjects (a priori subjects):**

Definition: subjects that exist before the protocol.  
Types: natural persons, legal entities, government agencies, and devices.

Characteristics:

- The registration event is an anchoring event (it links an already existing subject to verifiable history).
- The protocol does not create Type A subjects; it records their actions.
- EntityFingerprint is derived from real-world identity material.
- Potential is a logical state and does not correspond to a ClaimAnchor stored on-chain. It represents a subject that exists in the real world but has not yet been anchored in the protocol.

States: `Potential` (logical) → `Active` → `Grace` → `Expired` / `Revoked` / `Deregistered`.

**Type B subjects (derived subjects):**

Definition: subjects that come into existence when specific trigger conditions occur.  
Types: AI Agents, temporary proxies, and virtual entities.

Characteristics:

- The generation event creates the subject (the trigger condition is a prerequisite for existence).
- The lifecycle is entirely within the protocol framework.
- EntityFingerprint includes the deployer's fingerprint and cannot be separated from it.
- Type B subjects have no Potential state; they are generated directly into existence by the trigger event.

States: `Active` → `Grace` → `Expired` / `Revoked` / `Terminated`.

Key distinction:

Type A: the Potential state is exclusive to Type A (logical state).  
Type B: no Potential state; creation makes it Active.

### 2.3 Subjects are not created

Correct interpretation:

`ClaimAnchor.SubjectSignature` proves that the subject is aware of and consents to this claim.  
`ClaimAnchor.IrisSignature` proves that the endorser verified and endorsed this claim.

These two signatures do not “create” the subject; they “recognize” the subject's existence and cryptographically anchor its attributes to verifiable event timing.

Incorrect interpretations (avoid):

- ❌ “The L2 node created a user account.”
- ❌ “Registering a ClaimAnchor is registering a subject.”
- ✅ “The ClaimAnchor records that the subject declared an attribute at TI and received an endorsement.”

---

## 3. EntityFingerprint specification

EntityFingerprint is the cryptographic identity of a subject, derived by one-way hashing of real identity material.

**Core principles:**

- One-way: identity material cannot be recovered from EntityFingerprint.
- Deterministic: the same normalized input produces the same EntityFingerprint.
- Isolated: L2 nodes store EntityFingerprint, not the plaintext identity material.
- Stable: the same subject's EntityFingerprint remains unchanged over time.

### 3.1 Calculation overview

`EntityFingerprint = H(normalized identity-material byte sequence)`

`type_prefix` encoding:

**V4.1 security revision: EntityPrefix allowlist**

EntityFingerprint `type_prefix` accepts only the following values. Any prefix not on the allowlist MUST be rejected; a ClaimAnchor MUST NOT be issued.

| Prefix | Type | Description |
|:---:|---|---|
| `0x01` | Natural person | Identity-card number · passport number |
| `0x02` | Legal entity | Unified Social Credit Code |
| `0x03` | Device | Device fingerprint |
| `0x05` | Organization | Non-profit · government · international organization |
| `0x20` | AI Agent | Embeds `deployer_fp` · O(1) accountability |

Future additions SHALL update this allowlist.

Historical / legacy mapping:

```text
0x01 Natural person (mainland China resident identity card)
0x02 Mainland Travel Permit for Hong Kong / Macao / Taiwan residents or foreign passport
0x03 Unified Social Credit Code (legal entity)
0x04 Organization Code (legacy system; backward compatibility)
0x20 AI Agent
0x30 IoT device
0xFF Custom (private scenarios)
```

### 3.2 Natural person (resident identity card)

```text
EntityFingerprint = H(
    name_normalized ∥  // name, UTF-8 NFC normalization, no spaces
    0x01 ∥             // type_prefix
    id_number_upper    // 18-character identity-card number in uppercase (including check digit X)
)
```

Normalization rules (MUST):

`name_normalized`:

- Apply Unicode NFC normalization (composed form).
- Remove all leading and trailing whitespace (`trim`).
- Do not change letter case (preserve the original case of the name).

Encoding: UTF-8 byte sequence.

`id_number_upper`:

- ASCII byte sequence.
- Convert letters to uppercase (`X` is accepted as the identity-card check digit; lowercase `x` is not accepted).
- Remove all spaces and hyphens.
- Length MUST equal 18 bytes.

Example (for demonstration only; not real data):

```text
Name: Zhang San (the UTF-8 sample value is preserved below)
Identity-card number: 110101199001011234
```

```python
name_bytes = "\u5f20\u4e09".encode('utf-8')  # UTF-8 bytes for the sample name Zhang San
type_prefix = bytes([0x01])
id_bytes = b"110101199001011234"

EntityFingerprint = H(name_bytes ∥ type_prefix ∥ id_bytes)
```

### 3.3 Natural person (Hong Kong, Macao, Taiwan, or foreign national)

```text
EntityFingerprint = H(
    name_normalized ∥
    0x02 ∥
    cert_type(1 B) ∥       // certificate-type code (see table below)
    cert_number_upper      // certificate number, uppercase ASCII
)
```

`cert_type` encoding:

| Code | Certificate type |
|---|---|
| `0x01` | Hong Kong Resident Identity Card / Mainland Travel Permit (Home Return Permit) |
| `0x02` | Macao Resident Identity Card / Mainland Travel Permit |
| `0x03` | Taiwan Compatriot Entry Permit |
| `0x10` | Passport (general, including Chinese passports) |
| `0x11` | United States passport |
| `0x12` | Passport of a European Union member state |
| `0x20` | Foreigner Permanent Residence ID Card |

Normalization rules are the same as in §3.2; `cert_number_upper` is converted to uppercase.

### 3.4 Legal entity (Unified Social Credit Code)

```text
EntityFingerprint = H(
    0x03 ∥           // type_prefix
    uscc_upper       // Unified Social Credit Code, 18 uppercase ASCII characters
)
```

Note: a legal entity's EntityFingerprint does not include its name.
Reason: an enterprise's name may change while its USCC does not.
Store the enterprise name as an AttributeHash in ClaimAnchor (it can be updated).

Normalization rules for `uscc_upper`:

- Unified Social Credit Code, 18 characters.
- Convert letters to uppercase.
- Remove all spaces.
- Length MUST equal 18 bytes.

### 3.5 AI Agent

```text
EntityFingerprint = H(
    0x20 ∥                  // type_prefix (Type B subject marker)
    agent_public_key ∥      // 64 B SM2 public key (raw coordinate concatenation: x ∥ y, 32 B each, uncompressed format)
    deployer_fingerprint    // 32 B EntityFingerprint of the deployer
)
```

Note: SM2 public keys use uncompressed format (32 B x-coordinate + 32 B y-coordinate), conforming to the national cryptography standard.

Key design: the deployer's fingerprint is embedded permanently.

`deployer_fingerprint` is the EntityFingerprint of the deployer (a natural person or legal entity).
Once embedded, a verifier holding the Agent EntityFingerprint can identify the deployer without querying any external data.
The EntityFingerprint itself carries accountability information.

AI Agent generation rule (`GenerateSubjectCondition`):

The deployer MUST pre-register a `GenerateSubjectCondition` (see field design FLD-001).
Generation is triggered when the condition is met.
Calculate the generated ClaimAnchor's EntityFingerprint using the formula above.
The IssuerFingerprint is usually that of an AI governance institution or the deployer itself.

Multi-level AI Agents (an Agent generates another Agent):

If Agent_A generates Agent_B:

```text
Agent_B.deployer_fingerprint = Agent_A.EntityFingerprint
                            = H(0x20 ∥ AgentA_pubkey ∥ HumanDeployer_fp)
Accountability chain: Agent_B → Agent_A → natural person
```

DelegationDepth (P5 layer) MUST control the depth to prevent infinite recursion.

### 3.6 Device

```text
EntityFingerprint = H(
    0x30 ∥                 // type_prefix
    device_public_key ∥    // 64 B SM2 public key (uncompressed format)
    manufacturer_fingerprint  // 32 B manufacturer EntityFingerprint
)
```

Purpose of the manufacturer fingerprint: analogous to the deployer fingerprint for an AI Agent.
Accountability chain: device operation → device EntityFP → manufacturer EntityFP → manufacturer legal entity.

### 3.7 Normalization requirements (MUST)

All EntityFingerprint calculations MUST comply with the following normalization rules:

```python
def normalize_name(name: str) -> bytes:
    """Normalize a name."""
    import unicodedata
    # Step 1: Unicode NFC normalization
    normalized = unicodedata.normalize('NFC', name)
    # Step 2: Remove leading and trailing whitespace
    normalized = normalized.strip()
    # Step 3: Encode as UTF-8
    return normalized.encode('utf-8')

def normalize_id_number(id_num: str) -> bytes:
    """Normalize an identity-document number."""
    # Step 1: Remove all spaces and hyphens
    cleaned = id_num.replace(' ', '').replace('-', '')
    # Step 2: Convert to uppercase
    upper = cleaned.upper()
    # Step 3: Encode as ASCII bytes
    return upper.encode('ascii')

def normalize_uscc(uscc: str) -> bytes:
    """Normalize a Unified Social Credit Code."""
    cleaned = uscc.replace(' ', '').upper()
    assert len(cleaned) == 18, f"Incorrect USCC length: {len(cleaned)}"
    return cleaned.encode('ascii')

# Handling normalization failure:
# If the input does not meet the rules → return E_NORMALIZATION_FAILED and do not generate EntityFingerprint.
# The endorser MUST verify the normalization result before issuance.
```

## 4. ClaimAnchor data structure

### 4.1 Field definition (504 B)

A ClaimAnchor consists of EEA (224 B including VP) + ExtHeader (8 B) + payload (272 B).

Structure:

```text
EEA core fields (192 B)
VerificationProof (32 B, optional; included if the L2 node supports VP)
ExtensionHeader (8 B): extension_type=0x0102, hdr_flags.bit0=1 (critical)
Payload (272 B): see the table below
```

Payload field layout (272 B):

| Offset | Length | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 32 B | `EntityFingerprint` | `bytes[32]` | Calculation: see §3, varies by subject type. Meaning: the subject's cryptographic identity. |
| 32 | 32 B | `AttributeHash` | `bytes[32]` | Calculation: `H(attribute_content_canonical_bytes)`. Meaning: cryptographic commitment to attribute content; plaintext is not stored. `canonical_bytes` is deterministic serialization defined by the AttributeType specification. |
| 64 | 32 B | `IssuerFingerprint` | `bytes[32]` | Calculation: `H(issuer_SM2_public_key_bytes)`. Meaning: cryptographic identifier of the endorser. |
| 96 | 32 B | `PreviousClaimAnchor` | `bytes[32]` | Meaning: AnchorID of the previous version for the same EntityFingerprint + AttributeType. All zeros (`0³²`) = first issuance, no prior version. The version chain makes historical attribute changes undeletable and traceable. |
| 128 | 8 B | `ValidUntil` | `uint64` BE | Meaning: valid when `current_TI ≤ ValidUntil`. `0` = never expires (use cautiously; recommended only for root-certificate types). |
| 136 | 2 B | `AttributeType` | `uint16` BE | Meaning: attribute category proved by this ClaimAnchor. Encoding: see §5. |
| 138 | 6 B | `reserved_future` | `bytes[6]` | Meaning: 8-byte alignment extension slot. MUST currently be 0. Reserved for AttributeType / ValidUntil v2 extension. |
| 144 | 64 B | `SubjectSignature` | `bytes[64]` | Calculation: `Sign(sk_subject, H(subject_signing_payload))`. Signing input: see §4.2 (189 B). |
| 208 | 64 B | `IrisSignature` | `bytes[64]` | Calculation: `Sign(sk_issuer, H(iris_signing_payload))`. Signing input: see §4.3 (253 B). |
|  | **272 B** | **Payload total** |  |  |
|  | **504 B** | **ClaimAnchor total** |  | `224 + 8 + 272 = 504 B` |

### 4.2 SubjectSignature signing input (189 B)

```python
subject_signing_payload = (
    b"Iris.Claim.v1"             # 13 B domain_tag (prevents cross-protocol reuse)
    + EEA.AnchorID               # 32 B; binds to a specific EEA (prevents transplant attacks)
    + EntityFingerprint          # 32 B
    + AttributeHash              # 32 B
    + IssuerFingerprint          # 32 B
    + PreviousClaimAnchor        # 32 B
    + BE64(ValidUntil)           # 8 B
    + BE16(AttributeType)        # 2 B
    + reserved_future            # 6 B; all zeros; copied as-is in R3 slicing
)
total = 13+32+32+32+32+32+8+2+6 = 189 B

SubjectSignature = Sign(sk_subject, H(subject_signing_payload))
```

Semantics: the subject signs with its private key to prove:

- The subject knows about and consents to this attribute claim.
- The claim is bound to a specific EEA (temporal anchoring).
- The claim is associated with a specific endorser.

### 4.3 IrisSignature signing input (253 B)

```python
iris_signing_payload = (
    subject_signing_payload  # 189 B; complete signing input for SubjectSignature
    + SubjectSignature       # 64 B; the subject's signature itself
)
total = 189 + 64 = 253 B

IrisSignature = Sign(sk_issuer, H(iris_signing_payload))
```

Semantics: the endorser signs with its private key to prove:

- The institution verified the attribute content (the plaintext corresponding to AttributeHash).
- The institution confirmed that the subject was aware and consented (by covering SubjectSignature).
- The institution endorses the authenticity of the entire claim.

Security meaning of nesting: IrisSignature covers SubjectSignature, preventing an attacker from forging “the subject consented” and then requesting an institutional endorsement. When signing, the institution has seen the subject's signature and confirmed that the consent is genuine.

### 4.4 Semantics of nested signatures

Signature chain:

```text
Subject private-key signature → SubjectSignature
     ↓
Institution private-key signature (covers SubjectSignature) → IrisSignature
```

Verification order:

Step 1: Verify SubjectSignature (subject awareness and consent).  
Step 2: Verify IrisSignature (institutional endorsement, covering the subject signature).

Attack defenses:

**Attack A: An attacker forges the subject's consent and asks the institution to endorse it.**

→ The SubjectSignature seen by the institution is forged.  
→ The institution fails to verify SubjectSignature and rejects the endorsement.

**Attack B: An attacker replaces SubjectSignature.**

→ IrisSignature covers SubjectSignature.  
→ After replacement, IrisSignature verification fails.

**Attack C: An attacker transplants a ClaimAnchor endorsement to another EEA.**

→ SubjectSignature includes `EEA.AnchorID` (bytes 14–45 of the 189-byte input).  
→ Different EEAs have different AnchorIDs; after transplant, SubjectSignature verification fails.

### 4.5 Field-construction order

Step 1: Complete EEA generation and storage (obtain `EEA.AnchorID`).  
Step 2: Calculate EntityFingerprint by subject type (see §3).  
Step 3: Calculate `AttributeHash = H(attribute_content_canonical_bytes)`.  
Step 4: Determine ValidUntil according to endorser policy (MUST be ≤ `IssuerCertificate.valid_until`).  
Step 5: Obtain `IssuerFingerprint = H(issuer_public_key)`.  
Step 6: Look up `PreviousClaimAnchor` (the latest-version AnchorID for the same EntityFP + AttributeType).  
Step 7: Construct `subject_signing_payload` (189 B) and calculate SubjectSignature.  
Step 8: Construct `iris_signing_payload` (253 B) and calculate IrisSignature.  
Step 9: Assemble ExtensionHeader (`extension_type=0x0102`, `hdr_flags.bit0=1` (critical)).  
Step 10: Write to L2 node storage and update the `entity_current_claims` index.

## 5. AttributeType system

AttributeType is a 16-bit unsigned integer that defines the category of a subject's attribute.

### 5.1 Encoding rules

Encoding-space allocation:

| Range | Category |
|---|---|
| `0x0000` | Reserved; do not use |
| `0x0001–0x00FF` | KYC (personal identity) |
| `0x0100–0x01FF` | Qualifications (licenses · professional practice · certifications) |
| `0x0200–0x02FF` | Internal organization (roles · permissions · tenure) |
| `0x0300–0x03FF` | AI Agent (capabilities · authorization scope) |
| `0x0400–0x04FF` | Device |
| `0x0050–0x008F` | Privacy enhanced (yes/no; no ZKP needed) |
| `0xFF00–0xFFFF` | Custom (private; do not use across institutions) |

Encoding principle:

At one point in time, for the same EntityFingerprint, there may be at most one valid ClaimAnchor for each AttributeType (uniqueness constraint; enforced by L2 collision detection).

### 5.2 KYC types (personal identity)

| AttributeType | Name | Description |
|---|---|---|
| `0x0001` | `KYC_L1_BASIC` | Basic identity (name + identity-document-number verification). `AttributeHash = H({"name":..., "cert_type":..., "cert_no_hash":..., "pubkey_hash":...})`; the subject public-key hash may optionally be included. Minimum KYC level; suitable for general scenarios. |
| `0x0002` | `KYC_L2_STANDARD` | Standard identity (L1 + face matching + liveness detection). `AttributeHash = H({"kyc_l1_ref":..., "face_match_score":..., "liveness_passed":true, "verified_at":...})`. |
| `0x0003` | `KYC_L3_ENHANCED` | Enhanced identity (L2 + bank-card four-factor verification + anti-money-laundering check). Applicable to high-net-worth, cross-border, and compliance-sensitive scenarios. |
| `0x0010` | `ID_CHANGE` | Identity-change record (name change · document reissuance). AttributeHash includes references to the old and new identity documents. |
| `0x0020` | `ADDRESS_PROOF` | Proof of residence |
| `0x0021` | `CONTACT_VERIFIED` | Contact-method verification (mobile phone · email) |

### 5.3 KYB types (legal-entity identity)

| AttributeType | Name | Description |
|---|---|---|
| `0x0011` | `KYB_B1_BASIC` | Basic legal-entity identity (USCC + business-registration information). `AttributeHash = H({"uscc":..., "company_name_hash":..., "registered_capital":..., "reg_date":...})`. |
| `0x0012` | `KYB_B2_STANDARD` | Standard legal-entity identity (B1 + legal representative identity + business scope). AttributeHash includes a ClaimAnchor reference for the legal representative. |
| `0x0013` | `KYB_B3_ENHANCED` | Enhanced legal-entity identity (B2 + financial data + credit rating) |
| `0x0015` | `LEGAL_REP_CURRENT` | Current legal representative (changes frequently; independent type). `AttributeHash = H({"legal_rep_fp":..., "effective_from":...})`. |
| `0x0016` | `LEGAL_REP_HISTORY` | Historical legal-representative change record |
| `0x0020` | `BRANCH_RELATION` | Branch relationship (head office ↔ branch). AttributeHash includes a reference to the head-office EntityFingerprint. |
| `0x0021` | `EQUITY_STRUCTURE` | Equity structure (snapshot of the ten largest shareholders) |

### 5.4 Qualification types (licenses · professional practice)

| AttributeType | Name | Description |
|---|---|---|
| `0x0101` | `FIN_LICENSE` | Financial-industry qualification (funds · futures · insurance, etc.) |
| `0x0102` | `LAW_LICENSE` | Lawyer's license (including practice institution and specialty) |
| `0x0103` | `MED_LICENSE` | Medical license (physician · pharmacist · nurse) |
| `0x0104` | `AUDIT_LICENSE` | Certified Public Accountant license |
| `0x0105` | `SEC_LICENSE` | Securities-industry qualification |
| `0x0110` | `DOMAIN_EXPERT` | Domain-expert certification (issued by an industry institution) |
| `0x0120` | `GOVT_CLEARANCE` | Government security clearance (issued by a government agency) |

### 5.5 Internal-organization types (roles · permissions)

| AttributeType | Name | Description |
|---|---|---|
| `0x0201` | `ORG_ROLE` | Position within an organization. `AttributeHash = H({"org_fp":..., "role":..., "dept_hash":..., "tenure_from":...})`. |
| `0x0202` | `ORG_SCOPE` | Authorization scope within an organization (signing · procurement · agency permissions) |
| `0x0203` | `ORG_LEVEL` | Job-grade level (used for permission-tiering controls) |
| `0x0210` | `BOARD_MEMBER` | Board member (including independent-director flag) |
| `0x0211` | `LEGAL_REP_CHANGE` | Legal-representative change record (issued by an institution; triggers an update to `0x0015`) |
| `0x0220` | `PROXY_AUTH` | Authorized-agent proof (includes a reference to the delegator) |

### 5.6 AI Agent types

| AttributeType | Name | Description |
|---|---|---|
| `0x0301` | `AGENT_CAPABILITY` | AI Agent capability claim. `AttributeHash = H({"model_id":..., "capability_types":[...], "max_context_tokens":..., "evaluation_passed":...})`. `max_context_tokens` is the maximum context size and is for reference only; the verifier trusts the endorsing institution. Note: numeric fields in a capability claim are endorsed by the AI governance institution; the verifier trusts only the institution's signature and does not verify that the numeric values are true. |
| `0x0302` | `AGENT_SCOPE` | Permitted operation scope for an AI Agent. `AttributeHash = H({"allowed_domains":[...], "forbidden_actions":[...], "max_value_per_op":...})`; includes allowed business domains, expressly forbidden operations, and the value limit per operation. |
| `0x0303` | `AGENT_LINEAGE` | AI Agent lineage (deployment chain). `AttributeHash = H({"parent_agent_fp":..., "deploy_chain_depth":..., "root_deployer_fp":...})`; includes parent Agent fingerprint, if any, deployment-chain depth, and root deployer fingerprint. |
| `0x0310` | `AGENT_AUDIT` | AI Agent audit result (issued by a security evaluation institution) |
| `0x0311` | `AGENT_COMPLIANCE` | AI Agent compliance certificate (includes regulatory version) |

### 5.7 Privacy-enhanced types (yes/no)

Privacy-enhanced AttributeTypes store only a yes/no conclusion, not the original numeric value.
They provide fine-grained privacy protection and support most scenarios without ZKP.

| AttributeType | Name | Description |
|---|---|---|
| `0x0050` | `AGE_GE_18` | Age ≥ 18 (yes/no) |
| `0x0051` | `AGE_GE_21` | Age ≥ 21 |
| `0x0052` | `AGE_GE_60` | Age ≥ 60 (senior status) |
| `0x0053` | `AGE_LT_18` | Age < 18 (minor protection) |
| `0x0060` | `CREDIT_QUALIFIED` | Meets credit-rating threshold (yes/no; no numeric score) |
| `0x0061` | `AML_CLEARED` | Passed anti-money-laundering check |
| `0x0062` | `SANCTION_FREE` | No sanctions-list record |
| `0x0070` | `MAINLAND_RESIDENT` | Resident of mainland China (yes/no) |
| `0x0071` | `SPECIFIC_JURISDICTION` | Resident of a specified jurisdiction |
| `0x0080` | `QUALIFIED_INVESTOR` | Qualified investor (yes/no) |
| `0x0081` | `PROFESSIONAL_INVESTOR` | Professional investor |
| `0x0090` | `HAS_MEDICAL_LICENSE` | Holds a valid medical license (yes/no) |
| `0x0091` | `HAS_LAW_LICENSE` | Holds a valid lawyer's license |

AttributeHash calculation (yes/no types):

```text
AttributeHash = H(BE16(AttributeType) ∥ 0x01 ∥ BE64(verified_at_ti) ∥ issuer_salt)
0x01 = True (conclusion is yes)
0x00 = False (usually do not issue a False claim; simply do not issue it)
issuer_salt = random salt from the endorsing institution (32 B), preventing correlation across institutions
The endorsing institution generates and stores salt. During verification, it can disclose salt to prove the hash matches.
```

### 5.8 Custom types (`0xFF00–0xFFFF`)

Custom types are for internal enterprise scenarios and MUST NOT be used across institutions.

Rules:

- Meaningful only within the issuing institution.
- Stored by L2 nodes but not interpreted by them.
- A verifier at another institution MAY ignore a custom type (as it would an unknown ExtensionHeader).
- Custom types MUST NOT be submitted as standard types; standard types require the formal application process.
- The issuing institution defines the canonical format of AttributeHash.

## 6. Endorser trust chain

### 6.1 IssuerCertificate

An endorser obtains the permission to issue ClaimAnchors through an IssuerCertificate.

IssuerCertificate fields:

| Field | Length | Description |
|---|---:|---|
| `issuer_fingerprint` | 32 B | `H(issuer_SM2_pubkey)` |
| `issuer_public_key` | 64 B | SM2 public key (raw bytes) |
| `issuer_level` | 1 B | 1=L1 root; 2=L2; 3=L3 |
| `allowed_attribute_types` | `N × 2 B` | List of AttributeTypes this issuer may issue |
| `max_lifetime_ti` | 8 B | Maximum ValidUntil the issuer may issue (relative value) |
| `parent_issuer_fp` | 32 B | Parent institution fingerprint; all zeros = root institution |
| `parent_cert_sig` | 64 B | Parent institution's signature on this certificate |
| `root_sig` | 64 B | L1 root signature (on the entire certificate) |
| `valid_from` | 8 B | Effective TI |
| `valid_until` | 8 B | Expiration TI; `0` = never expires |
| `successor_fp` | 32 B | Fingerprint of the institution succeeding after key rotation; all zeros = none |
| `overlap_end_ti` | 8 B | TI at the end of the overlap period |

IssuerCertificate signing-input construction:

```text
signing_payload =
    "Iris.IssuerCert.v1"(18 B)
    ∥ issuer_fingerprint(32 B)
    ∥ BE64(issuer_level)          // extend 1 B to 8 B for alignment
    ∥ allowed_attribute_types(serialized)  // consecutive BE16 values
    ∥ BE64(valid_from)
    ∥ BE64(valid_until)
parent_cert_sig = Sign(sk_parent, H(signing_payload))  // parent-institution signature
root_sig = Sign(sk_root_L1, H(signing_payload))        // L1 root signature (directly issued to root institution)
```

### 6.2 Trust-chain levels

**L1 root endorser (Root Issuer):**

Operator: government agencies · central banks · supreme courts · national time-service agencies.  
Issuance authority: all AttributeTypes (full range).  
`issuer_level = 1`.  
Its IssuerCertificate is issued by an L1 node of GnomonSystem Time Source Technology Co., Ltd.  
Special permission: may revoke an IssuerCertificate of a subordinate institution.

**L2 endorser (Domain Issuer):**

Operator: banks · securities companies · certification bodies · industry associations.  
Issuance authority: within the `allowed_attribute_types` in its IssuerCertificate.  
`issuer_level = 2`.  
IssuerCertificate is issued by an L1 root endorser.  
MUST verify the applicant's business license, compliance qualifications, and technical capability.

**L3 endorser (Sub Issuer):**

Operator: internal enterprise institutions · industry alliances · platforms for specific scenarios.  
Issuance authority: a subset of AttributeTypes authorized by an L2 institution.  
`issuer_level = 3`.  
IssuerCertificate is issued by an L2 endorser.  
Typical scenario: a large enterprise issues employee role proofs internally (`0x0201`).

Maximum delegation depth: 3 levels (L1 → L2 → L3).  
An L3 issuer cannot issue an IssuerCertificate for L4.

### 6.3 `allowed_attribute_types` constraints

Constraint rules:

```text
Parent.allowed_attribute_types ⊇ Child.allowed_attribute_types
A child institution cannot issue an AttributeType not authorized by its parent.
```

When storing a ClaimAnchor, an L2 node MUST verify:

```text
ClaimAnchor.AttributeType ∈ IssuerCertificate.allowed_attribute_types
Violation → E_ATTR_NOT_ALLOWED (E_PERM_003)
```

Least-privilege principle (recommended):

When applying for an IssuerCertificate, an endorser SHOULD request only the range of AttributeTypes needed for its actual business.
Do not request “all types” (unless the applicant is an L1 root institution).

### 6.4 Trust-chain verification algorithm (pseudocode)

```python
def cert_signing_payload(cert: IssuerCertificate) -> bytes:
    """Construct IssuerCertificate signing input (for verifying parent_cert_sig and root_sig)."""
    allowed_attr_bytes = b"".join(BE16(attr) for attr in cert.allowed_attribute_types)
    payload = (
        b"Iris.IssuerCert.v1"  # 18 B
        + cert.issuer_fingerprint
        + (cert.issuer_level).to_bytes(8, 'big')  # extend 1 B to 8 B for alignment
        + allowed_attr_bytes
        + cert.valid_from.to_bytes(8, 'big')
        + cert.valid_until.to_bytes(8, 'big')
    )
    return H(payload)

def verify_issuer_chain(
    issuer_fp:       bytes,  # 32 B fingerprint of the endorser to verify
    attribute_type:  int,    # AttributeType to be issued
    at_ti:           int,    # verification-time TI
) -> tuple[bool, str]:
    """Verify the integrity of the endorser trust chain.
    Returns (is_valid, error_message).
    """
    visited = set()  # prevent circular references

    def check_cert(fp: bytes, depth: int = 0) -> tuple[bool, str]:
        if fp in visited:
            return False, "E_ISSUER_CYCLE: trust-chain cycle detected"
        visited.add(fp)

        cert = get_issuer_certificate(fp)
        if cert is None:
            return False, f"E_ISSUER_NOT_FOUND: institution {fp.hex()[:8]} is not registered"

        # Check validity period
        if not (cert.valid_from <= at_ti):
            return False, f"E_ISSUER_NOT_YET_VALID: institution is not yet valid at TI={at_ti}"
        if cert.valid_until != 0 and cert.valid_until < at_ti:
            return False, f"E_ISSUER_EXPIRED: institution has expired at TI={at_ti}"

        # Check revocation
        if is_issuer_revoked(fp, at_ti):
            return False, "E_ISSUER_REVOKED: institution has been revoked"

        # Check AttributeType permission
        if attribute_type not in cert.allowed_attribute_types:
            return False, f"E_ATTR_NOT_ALLOWED: institution cannot issue AttributeType={attribute_type:#06x}"

        # Verify parent-institution signature
        sig_payload = cert_signing_payload(cert)
        if cert.parent_issuer_fp == bytes(32):
            # Root institution: verify the L1 node signature
            ok = Verify(l1_root_pubkey, sig_payload, cert.root_sig)
            if not ok:
                return False, "E_ROOT_SIG_INVALID: L1 root signature is invalid"
            return True, ""
        else:
            # Non-root institution: recursively verify the parent institution
            parent_ok, parent_err = check_cert(cert.parent_issuer_fp, depth + 1)
            if not parent_ok:
                return False, f"E_PARENT_INVALID: parent-institution verification failed → {parent_err}"

            # Verify the parent institution's signature on this certificate
            parent_cert = get_issuer_certificate(cert.parent_issuer_fp)
            ok = Verify(parent_cert.public_key, sig_payload, cert.parent_cert_sig)
            if not ok:
                return False, "E_PARENT_SIG_INVALID: parent-institution signature is invalid"

            # Verify inherited permissions: child set must be a subset
            if not set(cert.allowed_attribute_types).issubset(
                    set(parent_cert.allowed_attribute_types)):
                return False, "E_ATTR_OVERFLOW: child-institution permissions exceed the parent institution's scope"

            return True, ""

    return check_cert(issuer_fp)

```

## 7. ClaimAnchor lifecycle

### 7.1 State machine

Type A subject state machine:

```text
Potential ──register──► Active ──validity_expires──► Grace
                             │                          │
                             │revoke                renew│  exceed_grace_period
                             ▼                          ▼         ▼
                          Revoked                    Active   Expired
                                                         │
                            ┌────────────────────────────┘
                            │ re-endorse
                            └──────────────────────► Active
                          Deregistered (voluntary deregistration; irreversible)
                          Terminated (subject terminated, e.g. deceased; irreversible)
```

Note: Potential is a logical state and does not correspond to a ClaimAnchor stored on-chain. It represents a subject that exists in the real world but has not yet been anchored in the protocol.

Type B subject state machine (no Potential state):

```text
[Trigger event] ──generate──► Active ──validity_expires──► Grace
                                  │                            │
                                  │revoke/cascade_revoke  renew│
                                  ▼                            ▼
                               Revoked                      Active
                               Terminated (conditional termination, e.g. authorization revoked)
```

Absorbing states (irreversible):

`Revoked` · `Deregistered` · `Terminated` · `Expired` (grace period exceeded without renewal).

Grace Period:

Default: 30 days (configurable in IssuerCertificate).  
During the grace period, the ClaimAnchor is still treated as valid (with a degradation notice).  
If it is not renewed before the end of the grace period → `Expired` (irreversible).

### 7.2 Version chain (PreviousClaimAnchor)

The same subject (`EntityFingerprint`) can have multiple versions of a ClaimAnchor for the same attribute type (`AttributeType`); the versions are connected through a version chain.

Version-chain rules:

- New version: `new.PreviousClaimAnchor = old.AnchorID`.
- First issuance: `PreviousClaimAnchor = all zeros (0³²)`.

Purpose of the version chain:

1. Historical traceability: view every historical version of an attribute.
2. Non-deletion: historical versions remain available even if the attribute is revoked.
3. Change proof: prove that an attribute had value X at a certain time (rather than its current value Y).

Version-chain validity constraints:

When `PreviousClaimAnchor` is not all zeros:

- The referenced ClaimAnchor record MUST exist.
- The referenced record's EntityFingerprint MUST match the current one.
- The referenced record's AttributeType SHOULD match the current one (a version chain across AttributeTypes is a special case and requires a stated reason).

L2 node storage:

- The `entity_current_claims` table stores only the currently valid ClaimAnchor.
- The complete version chain is in the `claim_anchors` table, which includes all historical versions.

### 7.3 Revocation rules

Revocation types:

**Voluntary revocation (requested by the subject):**

- `revocation_reason = 0x02` (voluntary deregistration).
- The subject submits a RevocationRecord through the endorser as an agent.
- After receiving the subject's signature or out-of-band authentication, the endorser initiates revocation.
- Effect: `ClaimAnchor.status → Revoked`.

**Security revocation (initiated by an institution):**

- `revocation_reason = 0x01` (security risk).
- Initiated by the issuing institution or its parent institution.
- Effect: `ClaimAnchor.status → Revoked`.

**Mandatory legal revocation:**

- `revocation_reason = 0x03` (legal mandate).
- Initiated by a regulatory agency, with `override_grace=1` (effective immediately).
- MUST include `regulation_reference` (hash of the legal basis).
- Effect: `ClaimAnchor.status → Revoked` immediately, skipping the grace period.

**Cascade revocation:**

- `revocation_reason = 0x04` (cascade revocation).
- Trigger: the parent subject (deployer / parent institution) is revoked.
- Effect: all subordinate ClaimAnchors are also marked Revoked.

Revocation propagation:

RevocationRecord is broadcast through SyncService.  
SLA: reach 99% of L2 nodes within 30 minutes.  
High-security scenarios: query L2 nodes in real time (do not rely on cache / TrustPackage).

### 7.4 Cascade revocation (AI Agent scenarios)

```python
MAX_CASCADE_DEPTH = 5  # maximum cascade depth; matches maximum P5 DelegationDepth

def cascade_revoke_agent(
    deployer_fp: bytes,   # 32 B EntityFingerprint of the deployer being revoked
    revoke_ti:    int,    # TI at which revocation takes effect
    reason:       int,    # revocation reason
) -> list[RevocationRecord]:
    """Cascade revocation: when a deployer is revoked,
    revoke ClaimAnchors of all AI Agents deployed by that party.
    """
    revocations = []

    # Query every AI Agent whose deployer is deployer_fp
    # EntityFingerprint = H(0x20 ∥ agent_pubkey ∥ deployer_fp)
    # deployer_fp is the lookup key (requires index support)
    agent_claims = query_agent_claims_by_deployer(deployer_fp)

    for claim in agent_claims:
        if claim.status in (ACTIVE, GRACE, PENDING):
            rr = RevocationRecord(
                claim_anchor_id     = claim.anchor_id,
                entity_fingerprint  = claim.entity_fingerprint,
                attribute_type      = 0,  # revoke all types
                revocation_time     = revoke_ti,
                revocation_reason   = 0x04,  # cascade revocation
                issuer_fingerprint  = deployer_fp,  # initiating party
                override_grace      = True,  # immediately effective
            )
            revocations.append(rr)

    # Broadcast as a batch
    broadcast_revocations_batch(revocations)
    return revocations

# Control cascade depth to prevent infinite recursion
def cascade_revoke_recursive(entity_fp: bytes, depth: int = 0):
    if depth > MAX_CASCADE_DEPTH:
        audit_log.warn(f"Cascade-revocation depth exceeded: {depth}")
        return
    sub_agents = query_agent_claims_by_deployer(entity_fp)
    for agent in sub_agents:
        cascade_revoke_agent(agent.entity_fingerprint, current_ti(), 0x04)
        cascade_revoke_recursive(agent.entity_fingerprint, depth + 1)
```

## 8. Privacy-protection mechanisms

### 8.1 Hash semantic isolation

L2 node storage policy (semantic-isolation principle):

Stored:

```text
EntityFingerprint (subject cryptographic identifier, 32 B)
AttributeType (type code, uint16)
AttributeHash (SM3 hash of attribute content, 32 B)
IssuerFingerprint (institution cryptographic identifier, 32 B)
ValidUntil (validity TI, uint64)
SubjectSignature · IrisSignature (signatures)
```

Not stored:

- Plaintext identity material such as identity-card number, name, and address.
- Raw attribute-content data (only AttributeHash is stored).
- Any information that could recover the subject's real identity.

Security boundary:

Even if an L2 node is completely controlled by an attacker, the attacker knows only that a subject has an attribute of a certain type and that an institution endorsed it; the attacker does not know the specific attribute content or the subject's real name.

### 8.2 WPO (Windowed Proof Observation)

WPO is a subset view of a ClaimAnchor collection; a verifier can see only the attributes it requested.

```python
def create_wpo(
    entity_fp:        bytes,           # 32 B subject fingerprint
    requested_types:  list[int],       # requested AttributeType list
    requester_fp:     bytes,           # 32 B requester fingerprint
    purpose:          str,             # plain-text description of query purpose
    purpose_hash:     bytes,           # 32 B H(purpose)
    at_ti:            int,             # verification-time TI
) -> WPO:
    """Generate a Windowed Proof Observation.
    Include only ClaimAnchors whose types are in requested_types.
    Other attributes are invisible to the requester, and their existence cannot be inferred.
    """
    # Verify that purpose matches purpose_hash (optional; subject decides whether to do this)
    if H(purpose.encode('utf-8')) != purpose_hash:
        raise ValueError("purpose_hash mismatch")

    wpo = WPO(
        entity_fp    = entity_fp,
        requester_fp = requester_fp,
        purpose_hash = purpose_hash,
        generated_at = at_ti,
        claims       = [],
    )

    for attr_type in requested_types:
        claim = get_current_claim(entity_fp, attr_type, at_ti)
        if claim and is_valid(claim, at_ti):
            wpo.claims.append(claim)
        # If a type does not exist or is invalid, it is not represented in the WPO.
        # The verifier sees “not included” and cannot distinguish “does not exist” from
        # “the subject refused to disclose it.”

    # Sign the WPO with the subject or an authorized party to prevent tampering.
    wpo.subject_sig = Sign(sk_subject, H(wpo_signing_payload(wpo)))
    return wpo

def verify_wpo(wpo: WPO, at_ti: int) -> bool:
    """Verify WPO integrity and the validity of each ClaimAnchor."""
    # Verify the WPO signature
    if not Verify(get_subject_pubkey(wpo.entity_fp),
                  wpo_signing_payload(wpo),
                  wpo.subject_sig):
        return False
    # Verify every ClaimAnchor
    for claim in wpo.claims:
        if claim.entity_fingerprint != wpo.entity_fp:
            return False
        if not verify_claim_anchor(claim, at_ti):
            return False
    return True
```

Privacy semantics of WPO:

What the verifier can learn from WPO:

- ✅ The subject really has the listed attributes (valid ClaimAnchors).
- ✅ An endorser verified those attributes.

What the verifier cannot learn from WPO:

- ❌ Whether the subject has any other attributes.
- ❌ The specific values of the attributes (only AttributeHash is shown).
- ❌ The subject's activity in other contexts (see DerivedFingerprint).

### 8.3 DerivedFingerprint

DerivedFingerprint protects against cross-context correlation: the same subject uses a different identifier in each context.

```text
DerivedFingerprint = H(
    EntityFingerprint      (32 B) real subject fingerprint
  ∥ scope_salt              (32 B) context salt (provided by the context operator)
  ∥ issuer_fingerprint      (32 B) endorser fingerprint
)
```

Design intent:

An attacker holding `DerivedFP_A` from Context A and `DerivedFP_B` from Context B cannot determine whether they came from the same subject.
Only the subject (which holds EntityFingerprint) can derive the relationship between the two.

Usage rules:

- Use DerivedFingerprint for privacy protection within a specific context.
- Within that context, use DerivedFP instead of EntityFP.
- The context operator knows `scope_salt` and can verify that DerivedFP is correct.
- The context operator does not know EntityFP and cannot correlate across contexts.
- The context operator SHOULD protect `scope_salt`; after it is lost, the correctness of DerivedFingerprint cannot be verified.

Use cases:

- Healthcare system: a patient uses different DerivedFPs at Hospital A and Hospital B.
- Financial system: a user uses a different DerivedFP at each bank.
- Cross-platform authentication: prevent platforms from tracking a user by identity identifier.

Limitations:

- DerivedFP cannot be stored as the ClaimAnchor's EntityFingerprint (ClaimAnchor MUST use the real EntityFingerprint).
- DerivedFP is only for references within a context; it is not written to L2 nodes.

### 8.4 Reserved ZKP interface

`extension_type = 0x0103` (ZKP ClaimAnchor).

Current status: reserved; not implemented in V1.0.  
Pending: publication of a national cryptography authority post-quantum / ZKP standard.

Reserved interface definition:

```text
payload = {
  circuit_id:     bytes[32]  // ZKP circuit identifier (SM3(circuit definition))
  public_inputs:  bytes[N]   // public inputs (conclusion visible to verifier)
  proof:          bytes[M]   // ZKP proof byte sequence
  commitment:     bytes[32]  // SM3(original attribute content), backward compatible
}
```

Downgrade handling (`hdr_flags.bit0=0`, non-critical):

A node that does not support ZKP uses the `commitment` field for ordinary AttributeHash verification.  
Return `W012` (ZKP degraded).

ZKP use cases (planned for V2.0):

- Continuous-value range proof: income is within [X,Y], without disclosing the exact value.
- Set-membership proof: the subject belongs to a whitelist, without disclosing which member.
- Multi-attribute combined proof: prove A ∧ B ∧ C without disclosing each attribute separately.

## 9. Verification specification

### 9.1 Full ClaimAnchor verification algorithm

```python
def get_subject_public_key(claim: ClaimAnchor) -> bytes:
    """Obtain the subject's public key.

    The subject's public key is not stored in ClaimAnchor. Obtain it as follows:
      1. If the KYC attribute (AttributeType 0x0001) contains pubkey_hash,
         obtain the public-key hash from that KYC ClaimAnchor, then look up the
         public key in external storage.
      2. If the subject registered a public key in advance, look it up in the
         subject registry by EntityFingerprint.
      3. If neither method is possible, verification fails (return
         E_SUBJECT_PUBKEY_NOT_FOUND).

    Recommendation: AttributeHash in KYC_L1_BASIC (0x0001) SHOULD contain the
    subject public-key hash, and the endorser SHOULD verify the binding between
    the public key and the identity.
    """
    # Implementation omitted: lookup logic is implemented by the L2 node or verifier.
    pass

def verify_claim_anchor(
    claim: ClaimAnchor,
    at_ti: int | None = None,  # verification time; None = use claim's EEA.TI
) -> VerifyResult:
    """Full ClaimAnchor verification algorithm (six steps).
    at_ti determines the time-cut basis.
    """
    result = VerifyResult()
    check_ti = at_ti if at_ti is not None else claim.eea.temporal_index

    # ── Step 1: Verify the EEA base layer (P2) ────────────────
    eea_result = verify_eea_full(claim.eea, verify_depth=2, at_ti=check_ti)
    if not eea_result.valid:
        return VerifyResult(valid=False, error=E_EEA_INVALID,
                            detail=eea_result.error)

    # ── Step 2: Verify ExtensionHeader ───────────────────────
    if claim.extension_type != 0x0102:
        return VerifyResult(valid=False, error=E_WRONG_EXT_TYPE)
    if not (hdr_flags & 0x01):
        return VerifyResult(valid=False, error=E_CRITICAL_FLAG)

    # ── Step 3: Verify endorser trust chain ──────────────────
    issuer_ok, issuer_err = verify_issuer_chain(
        claim.issuer_fingerprint,
        claim.attribute_type,
        check_ti,
    )
    if not issuer_ok:
        return VerifyResult(valid=False, error=E_ISSUER_INVALID,
                            detail=issuer_err)

    # ── Step 4: Verify validity period (time cut) ────────────
    if claim.valid_until != 0 and claim.valid_until < check_ti:
        return VerifyResult(valid=False, error=E_CLAIM_EXPIRED,
                            detail=f"ValidUntil={claim.valid_until}, at_ti={check_ti}")

    # ── Step 5: Verify revocation status (time cut) ─────────
    rev_status = verify_revocation_status(claim.anchor_id, check_ti)
    if rev_status.is_revoked:
        return VerifyResult(valid=False, error=E_CLAIM_REVOKED,
                            detail=f"Revocation time TI={rev_status.revoked_at}")

    # ── Step 6: Verify signature chain ──────────────────────

    # 6a: Reconstruct subject_signing_payload (189 B)
    subject_payload_raw = (
        b"Iris.Claim.v1"                         # 13 B
        + claim.eea.anchor_id                    # 32 B
        + claim.entity_fingerprint               # 32 B
        + claim.attribute_hash                   # 32 B
        + claim.issuer_fingerprint               # 32 B
        + claim.previous_claim_anchor            # 32 B
        + claim.valid_until.to_bytes(8, 'big')   # 8 B
        + claim.attribute_type.to_bytes(2, 'big')  # 2 B
        + bytes(6)                               # reserved_future: 6 B, MUST=0, 8-byte alignment
    )
    assert len(subject_payload_raw) == 189

    # 6b: Verify SubjectSignature
    subject_pk = get_subject_public_key(claim)
    if subject_pk is None:
        return VerifyResult(valid=False, error=E_SUBJECT_PUBKEY_NOT_FOUND)
    if not Verify(subject_pk, H(subject_payload_raw), claim.subject_signature):
        return VerifyResult(valid=False, error=E_SUBJECT_SIG_INVALID)

    # 6c: Reconstruct iris_signing_payload (253 B)
    iris_payload_raw = subject_payload_raw + claim.subject_signature  # 189+64
    assert len(iris_payload_raw) == 253

    # 6d: Verify IrisSignature
    issuer_cert = get_issuer_certificate(claim.issuer_fingerprint)
    if not Verify(issuer_cert.public_key, H(iris_payload_raw), claim.iris_signature):
        return VerifyResult(valid=False, error=E_IRIS_SIG_INVALID)

    # ── Step 7: Verify PreviousClaimAnchor (version-chain integrity) ───
    if claim.previous_claim_anchor != bytes(32):
        prev = get_claim_anchor(claim.previous_claim_anchor)
        if prev is None:
            result.add_warning(W_PREV_CLAIM_NOT_FOUND,
                               "Previous ClaimAnchor is not present on this node")
        elif prev.entity_fingerprint != claim.entity_fingerprint:
            return VerifyResult(valid=False, error=E_CHAIN_FP_MISMATCH,
                                detail="EntityFingerprint does not match across the version chain")

    result.valid = True
    result.check_ti = check_ti
    result.claim_anchor = claim
    return result
```

### 9.2 Time-cut verification

Time-cut verification is one of the most important verification semantics in the Iris Protocol.

Time-cut rules:

Verification time `at_ti = EEA.TemporalIndex` (default):

“Was this ClaimAnchor valid when the event occurred?”  
This is the most common verification scenario.

Verification time `at_ti = current TI`:

“Is this ClaimAnchor valid now?”  
Used for real-time identity checks.

Verification time `at_ti = historical TI`:

“Was this ClaimAnchor valid at some time in the past?”  
Used for historical audits and judicial evidence.

Detailed rules:

Validity-period check:

- `ValidUntil = 0` → never expires (valid for any `at_ti`).
- `ValidUntil > 0` → valid when `at_ti ≤ ValidUntil`.

Revocation check:

- `RevocationRecord.revocation_time = T_revoke`.
- `at_ti < T_revoke` → before revocation; ClaimAnchor is valid.
- `at_ti ≥ T_revoke` → after revocation; ClaimAnchor is invalid.

Typical scenarios:

Contract signing (`EEA.TI = T_sign`):

Verify whether both parties' KYC was valid at signing → `at_ti = T_sign`.  
Even if KYC is revoked after `T_sign`, the contract was still valid at `T_sign`.

Real-time identity verification:

Is the current user's KYC valid now? → `at_ti = current_TI`.  
Revoked KYC cannot be used immediately.

### 9.3 Verification output format

```json
{
  "valid": true,
  "check_ti": 1000000001,
  "entity_fingerprint": "hex(32B)",
  "attribute_type": "0x0002",
  "attribute_type_name": "KYC_L2_STANDARD",
  "valid_until": 2000000000,
  "issuer_fingerprint": "hex(32B)",
  "issuer_level": 2,
  "chain_depth": 2,
  "eea_anchor_id": "hex(32B)",
  "claim_anchor_id": "hex(32B)",
  "version_chain_length": 3,
  "revocation_status": "NOT_REVOKED",
  "warnings": [],
  "is_degraded_eea": false
}
```

## 10. Protocol messages (Protobuf)

```protobuf
// gnomon/v1/iris.proto
syntax = "proto3";
package gnomon.v1;

// ── Core data structures ──────────────────────────────────
message ClaimAnchor {
  uint32 version                 = 1;
  bytes  anchor_id               = 2;   // 32 B
  EEA    eea                     = 3;   // complete EEA (224 B including VP)

  // P3 payload fields
  bytes  entity_fingerprint      = 4;   // 32 B
  uint32 attribute_type          = 5;   // uint16
  bytes  attribute_hash          = 6;   // 32 B
  uint64 valid_until             = 7;   // 0 = never expires
  bytes  issuer_fingerprint      = 8;   // 32 B
  bytes  previous_claim_anchor   = 9;   // 32 B; all zeros = first issuance
  bytes  subject_signature       = 10;  // 64 B
  bytes  iris_signature          = 11;  // 64 B

  // Extensions (ZKP · delegation · federation endorsement)
  ClaimExtension extension       = 12;
}

message ClaimExtension {
  uint32 extension_type = 1;
  // 0x0103=ZKP  0x0104=DelegatedClaim  0x0105=FederatedClaim
  bytes  payload        = 2;
}

message IssuerCertificate {
  uint32 version                    = 1;
  bytes  issuer_fingerprint         = 2;   // 32 B
  bytes  issuer_public_key          = 3;   // 64 B
  uint32 issuer_level               = 4;   // 1 · 2 · 3
  repeated uint32 allowed_attr_types = 5;  // uint16 list
  uint64 max_lifetime_ti            = 6;
  bytes  parent_issuer_fp           = 7;   // 32 B; all zeros = root institution
  bytes  parent_cert_sig            = 8;   // 64 B
  bytes  root_sig                   = 9;   // 64 B
  uint64 valid_from                 = 10;
  uint64 valid_until                = 11;
  bytes  successor_fp               = 12;  // 32 B; all zeros = none
  uint64 overlap_end_ti             = 13;
}

// ── Iris service ──────────────────────────────────────────
service IrisService {
  // Submit a ClaimAnchor (endorser → L2 node)
  rpc SubmitClaimAnchor(SubmitClaimRequest) returns (SubmitClaimResponse);

  // Get a subject's currently valid ClaimAnchor
  rpc GetCurrentClaim(GetCurrentClaimRequest) returns (GetCurrentClaimResponse);

  // Get a subject's ClaimAnchor status at a given time (time cut)
  rpc GetClaimAtTime(GetClaimAtTimeRequest) returns (GetClaimAtTimeResponse);

  // Get a subject's ClaimAnchor version chain
  rpc GetClaimHistory(GetClaimHistoryRequest) returns (GetClaimHistoryResponse);

  // Verify a ClaimAnchor (complete six-step verification)
  rpc VerifyClaimAnchor(VerifyClaimRequest) returns (VerifyClaimResponse);

  // Submit a revocation record
  rpc SubmitRevocation(SubmitRevocationRequest) returns (SubmitRevocationResponse);

  // Register an endorser
  rpc RegisterIssuer(RegisterIssuerRequest) returns (GnomonResponse);

  // Get endorser information
  rpc GetIssuerCertificate(GetIssuerRequest) returns (GetIssuerResponse);

  // Generate a WPO (observation window)
  rpc CreateWPO(CreateWPORequest) returns (CreateWPOResponse);

  // Query events in which a subject participated (reverse lookup through SemanticAnchor)
  rpc QuerySubjectEvents(QuerySubjectEventsRequest) returns (QuerySubjectEventsResponse);
}

message SubmitClaimRequest {
  uint32      version      = 1;
  ClaimAnchor claim_anchor = 2;
}

message SubmitClaimResponse {
  GnomonResponse response      = 1;
  bytes          anchor_id     = 2;   // 32 B
  uint64         stored_at_ti  = 3;
}

message GetCurrentClaimRequest {
  uint32 version            = 1;
  bytes  entity_fingerprint = 2;   // 32 B
  uint32 attribute_type     = 3;   // 0 = query all types
}

message GetCurrentClaimResponse {
  GnomonResponse       response = 1;
  repeated ClaimAnchor claims   = 2;
}

message GetClaimAtTimeRequest {
  uint32 version            = 1;
  bytes  entity_fingerprint = 2;   // 32 B
  uint32 attribute_type     = 3;
  uint64 at_ti              = 4;   // status at this TI
}

message GetClaimAtTimeResponse {
  GnomonResponse response     = 1;
  ClaimAnchor    claim_anchor = 2;
  bool           was_valid    = 3;
  bool           was_revoked  = 4;
  uint64         revoked_at   = 5;
}

message VerifyClaimRequest {
  uint32 version    = 1;
  bytes  anchor_id  = 2;   // 32 B
  uint64 at_ti      = 3;   // 0 = use ClaimAnchor's own EEA.TI
}

message VerifyClaimResponse {
  GnomonResponse response              = 1;
  bool           valid                 = 2;
  uint64         check_ti              = 3;
  bytes          entity_fingerprint    = 4;   // 32 B
  uint32         attribute_type        = 5;
  string         attribute_type_name   = 6;
  uint64         valid_until           = 7;
  bytes          issuer_fingerprint    = 8;   // 32 B
  uint32         issuer_level          = 9;
  uint32         chain_depth           = 10;
  uint32         version_chain_length  = 11;
  repeated uint32 warnings             = 12;
}

message CreateWPORequest {
  uint32         version            = 1;
  bytes          entity_fingerprint = 2;   // 32 B
  repeated uint32 requested_types  = 3;
  bytes          requester_fp      = 4;   // 32 B
  string         purpose           = 5;   // plain-text purpose
  bytes          purpose_hash      = 6;   // 32 B H(purpose)
  uint64         at_ti             = 7;
}

message WPO {
  bytes          entity_fp    = 1;   // 32 B
  bytes          requester_fp = 2;   // 32 B
  bytes          purpose_hash = 3;   // 32 B
  uint64         generated_at = 4;
  repeated ClaimAnchor claims = 5;
  bytes          subject_sig  = 6;   // 64 B
}

message CreateWPOResponse {
  GnomonResponse response = 1;
  WPO            wpo      = 2;
}

message QuerySubjectEventsRequest {
  uint32      version         = 1;
  bytes       claim_anchor_id = 2;   // 32 B; a ClaimAnchor of the subject
  PageRequest page            = 3;
}

message QuerySubjectEventsResponse {
  GnomonResponse       response = 1;
  repeated SubjectEvent events  = 2;
  PageResponse         page     = 3;
}

message SubjectEvent {
  bytes  eea_anchor_id   = 1;   // 32 B
  uint64 temporal_index  = 2;
  bytes  semantic_anchor = 3;   // 32 B
  bytes  p4_ref          = 4;   // 32 B, optional
  bytes  p5_ref          = 5;   // 32 B, optional
}
```

## 11. Security considerations

### 11.1 Irreversibility of EntityFingerprint

`EntityFingerprint = H(normalized identity material)`.

Security relies on SM3 one-wayness (preimage resistance).  
Quantum security: SM3 is secure against Grover's algorithm (128-bit equivalent); no migration is needed.

Attacks:

**Preimage attack:** An attacker holds an EntityFingerprint and tries to recover the name + identity-card number.  
Defense: an SM3 preimage attack requires `2^128` work and is infeasible.

**Dictionary attack:** Enumerate common name + identity-card-number combinations (China's population is about 1.4 billion).  
Defense: even enumerating 1.4 billion records requires about 1.4 billion SM3 hashes. With GPU acceleration this may take only seconds, so some risk exists.  
Additional protection: `AttributeHash = H(content ∥ issuer_salt)`; `issuer_salt` prevents correlation-based inference between endorsers.

### 11.2 Scope of impact from a malicious endorser

Maximum impact of a malicious endorser:

- It can affect only ClaimAnchors issued by that institution.
- It cannot affect ClaimAnchors issued by other institutions.
- It cannot affect EEA timing (the P2 layer is independent).

Detection mechanisms:

- A regulator node can query all ClaimAnchors issued by an institution.
- An abnormal issuance volume (a sudden bulk issuance) triggers an alert.
- A parent institution can revoke a subordinate institution's IssuerCertificate.

Emergency response:

- Once institutional misconduct is detected → the parent institution revokes its IssuerCertificate.
- Already issued ClaimAnchors can be revoked in bulk (use a bulk RevocationRecord with an all-zero `entity_fingerprint`).
- Completed collaboration cannot be revoked retroactively (time-cut protects completed lawful transactions).

### 11.3 Cryptographic guarantees for AI Agent accountability

Cryptographic accountability path:

```text
EEA.SemanticAnchor (P3+P5 combination)
  → P3_ref = Agent.ClaimAnchor.AnchorID
  → Agent.ClaimAnchor.EntityFingerprint
      = H(0x20 ∥ agent_pubkey ∥ deployer_fp)
  → deployer_fp is deployer.EntityFingerprint
  → deployer.ClaimAnchor → natural person / legal entity
```

Every link has a cryptographic guarantee:

1. EEA timing cannot be forged (ChainProof).
2. SemanticAnchor is bound to the EEA (AnchorID is embedded).
3. The Agent fingerprint contains the deployer and cannot be separated from it.
4. The deployer's ClaimAnchor was verified by an endorser.

Conclusion:

An attacker cannot break any link in the accountability chain.
Even if the attacker controls the Agent, the attacker cannot change `deployer_fp` inside the Agent fingerprint.

## 12. Test vectors

### 12.1 EntityFingerprint test vectors

```python
import hashlib, unicodedata

def sm3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()  # demonstration only; use national SM3 in production

# Test vector 1: natural person (resident identity card)
name    = "\u5f20\u4e09"  # sample name Zhang San; preserves the source vector's UTF-8 input
id_num  = "110101199001011234"

name_normalized = unicodedata.normalize('NFC', name).strip().encode('utf-8')
type_prefix     = bytes([0x01])
id_upper        = id_num.upper().encode('ascii')

efp_human = sm3(name_normalized + type_prefix + id_upper)
print(f"EntityFingerprint (natural person): {efp_human.hex()}")
# Implementations MUST match this output.

# Test vector 2: legal entity (USCC)
uscc = "91110000717919617H"
uscc_normalized = uscc.upper().encode('ascii')
efp_corp = sm3(bytes([0x03]) + uscc_normalized)
print(f"EntityFingerprint (legal entity): {efp_corp.hex()}")

# Test vector 3: AI Agent (64 B uncompressed public key)
agent_pubkey = bytes.fromhex("cc" * 64)   # 64 B SM2 public key (x ∥ y)
deployer_fp  = efp_human                   # use the natural-person fingerprint above
efp_agent = sm3(bytes([0x20]) + agent_pubkey + deployer_fp)
print(f"EntityFingerprint (AI Agent): {efp_agent.hex()}")
# Check that efp_agent contains deployer_fp and cryptographically binds the accountability path.
```

### 12.2 SubjectSignature signing-input length validation

```python
# Verify the 189 B signing input
EEA_ANCHOR_ID = bytes.fromhex("11" * 32)
ENTITY_FP     = efp_human
ATTR_TYPE     = 0x0002   # KYC_L2_STANDARD
ATTR_HASH     = bytes.fromhex("22" * 32)
VALID_UNTIL   = 2000000000
ISSUER_FP     = bytes.fromhex("33" * 32)
PREV_CLAIM    = bytes(32)  # first issuance; all zeros

raw = (
    b"Iris.Claim.v1"               # 13 B
    + EEA_ANCHOR_ID                # 32 B
    + ENTITY_FP                    # 32 B
    + ATTR_HASH                    # 32 B
    + ISSUER_FP                    # 32 B
    + PREV_CLAIM                   # 32 B
    + VALID_UNTIL.to_bytes(8,'big')  # 8 B
    + ATTR_TYPE.to_bytes(2,'big')    # 2 B
    + bytes(6)                     # reserved_future: 6 B, MUST=0
)
assert len(raw) == 189, f"Incorrect signing-input length: {len(raw)}"
subject_signing_hash = sm3(raw)
print(f"SubjectSignature signing hash: {subject_signing_hash.hex()}")

# IrisSignature signing input (253 B)
SUBJECT_SIG = bytes.fromhex("44" * 64)  # assumed SubjectSignature
iris_raw = raw + SUBJECT_SIG  # 189 + 64 = 253 B
assert len(iris_raw) == 253
iris_signing_hash = sm3(iris_raw)
print(f"IrisSignature signing hash: {iris_signing_hash.hex()}")
```

### 12.3 Trust-chain verification test cases

```python
# Verify that an L2 institution cannot issue an AttributeType reserved for L1
def test_attr_permission():
    l2_cert = IssuerCertificate(
        issuer_level = 2,
        allowed_attribute_types = [0x0001, 0x0002, 0x0003],  # KYC types
    )
    # Attempt to issue 0x0201 (organizational role); the L2 institution is not authorized.
    ok, err = verify_issuer_chain(l2_cert.issuer_fp, 0x0201, current_ti())
    assert not ok
    assert "E_ATTR_NOT_ALLOWED" in err
    print("✅ AttributeType permission-constraint test passed")

# Verify cascade revocation
def test_cascade_revoke():
    deployer_fp = efp_human
    agent_efp    = efp_agent
    # Revoke the deployer
    rrs = cascade_revoke_agent(deployer_fp, current_ti(), 0x04)
    # Verify that the Agent ClaimAnchor was revoked
    status = verify_revocation_status(agent_claim_anchor_id, current_ti())
    assert status.is_revoked
    print("✅ AI Agent cascade-revocation test passed")
```

## 13. Error and warning codes

P3 Iris Protocol error codes:

| Code | Meaning |
|---|---|
| `E_EEA_INVALID` | EEA base verification failed (depends on P2) |
| `E_WRONG_EXT_TYPE` | `ExtensionHeader.extension_type` is not `0x0102` |
| `E_CRITICAL_FLAG` | `hdr_flags.bit0` (critical) is not 1 |
| `E_ISSUER_NOT_FOUND` | Endorser is not registered |
| `E_ISSUER_EXPIRED` | Endorser certificate expired at `check_ti` |
| `E_ISSUER_REVOKED` | Endorser has been revoked |
| `E_ISSUER_CYCLE` | Trust chain contains a circular reference |
| `E_ATTR_NOT_ALLOWED` | Institution is not authorized to issue this AttributeType |
| `E_ATTR_OVERFLOW` | Subordinate institution's permissions exceed those of its parent |
| `E_CLAIM_EXPIRED` | ClaimAnchor expired at `check_ti` |
| `E_CLAIM_REVOKED` | ClaimAnchor had been revoked at `check_ti` |
| `E_SUBJECT_SIG_INVALID` | SubjectSignature verification failed |
| `E_IRIS_SIG_INVALID` | IrisSignature verification failed |
| `E_CHAIN_FP_MISMATCH` | EntityFingerprint differs across the version chain |
| `E_NORMALIZATION_FAILED` | EntityFingerprint normalization failed |
| `E_DUPLICATE_CLAIM` | A valid ClaimAnchor already exists for the same EntityFP + AttributeType |
| `E_SUBJECT_PUBKEY_NOT_FOUND` | Could not obtain the subject public key to verify SubjectSignature |

Warning codes:

| Code | Meaning |
|---|---|
| `W_CLAIM_EXPIRING` | ClaimAnchor is about to expire (less than 30 days) |
| `W_PREV_CLAIM_NOT_FOUND` | Previous ClaimAnchor is not on this node (cross-node synchronization delay) |
| `W_GRACE_PERIOD` | ClaimAnchor is in the grace period (past ValidUntil but still within grace period) |
| `W012` · `ZKP_DEGRADED` | ZKP is unsupported; downgraded to commitment verification |
| `W_DERIVED_FP_USED` | DerivedFingerprint is used in a WPO (privacy scenario) |

## 14. Version history

| Version | Date | Description |
|---|---|---|
| V3.7 | 2026-06-18 | Full-layout field reordering: removed the 2-byte Reserved field inserted by the lite layout and reordered fields to place `bytes[32]` first, followed by `uint64`, `uint16`, and the signature layout. Payload changed from 268 B to 266 B; Anchor from 500 B to 498 B. Signing inputs changed from 185 B to 183 B / 249 B to 247 B; field order now follows physical layout order. |
| V3.6 | 2026-06-18 | Expanded ExtHeader from 6 B to 8 B (added 2 B Reserved); ClaimAnchor total size changed from 498 B to 500 B. Signing-input lengths unchanged. |
| V1.2 | 2026-06-04 | Synchronized with P2's finalized EventAnchor 192 B / EEA 224 B convention. Adjusted ClaimAnchor total size to 498 B (224 B EEA + 6 B ExtensionHeader + 268 B payload); updated Protobuf comments and size descriptions. |
| V1.1 | 2026-06-03 | Added the method for obtaining the subject public key (added E_SUBJECT_PUBKEY_NOT_FOUND); specified the AI Agent public-key format (64 B, uncompressed); clarified that Potential is a logical state; added the trust-chain signing-input construction formula; clarified the subject revocation-delegation mechanism; defined maximum cascade-revocation depth (`MAX_CASCADE_DEPTH=5`); improved WPO purpose validation; added DerivedFingerprint salt-management recommendations; other small optimizations. |
| V1.0 | 2026-06 | Official release · design frozen. Complete definitions: Type A / Type B subjects; EntityFingerprint calculation (five subject types and normalization rules); legacy ClaimAnchor structure; dual signatures (185 B + 249 B); complete AttributeType encoding system (KYC / KYB / qualifications / organizational / AI / privacy-enhanced / custom); endorser trust chain (L1/L2/L3, `allowed_attribute_types` constraints, verification pseudocode); state machine; version chain; revocation (time cut); AI Agent cascade revocation; WPO; DerivedFingerprint; reserved ZKP; complete verification pseudocode; Protobuf messages; test vectors; error codes. |
| V4.2 | 2026-08-02 | Baseline V4.1 → V4.2: aligned header/footer version numbers, dates, and global labels to v4.2 · 2026-08-02. Reorganized the V4.1 revision block: removed “source” notes from the RFC body, retained normative constraints, and removed duplicate issuance-precondition blocks. |
| V4.1 | 2026-07-20 | Security revision: EntityPrefix allowlist (`0x01/02/03/05/20`; reject unknown prefixes); ClaimAnchor issuance preconditions (uniqueness by state · pre-issuance state check · Issuer ACL authorization check). Historical anchors are unaffected. |
| V4.0 | 2026-06-20 | V7b five-layer 8-byte alignment: `reserved_future` +6 B · Anchor +6 B · 12-level signature +6 B. |

## Release review items (non-normative)

The V4.4 source specification contains interoperability conflicts that must be resolved before this English edition is marked normative:

1. **EntityPrefix conflict:** The security allowlist specifies `0x02` for legal entities, `0x03` for devices, and `0x05` for organizations. The detailed algorithms instead use `0x02` for non-mainland natural persons, `0x03` for legal entities, and `0x30` for devices. The older type list also includes `0x04`, `0x30`, and `0xFF`, which are absent from the allowlist.
2. **AttributeType encoding conflicts:** `0x0020` and `0x0021` are assigned to different KYC/KYB claims. The privacy-enhanced range is described as overlapping the general KYC range, and `0x0090` / `0x0091` fall outside the stated `0x0050–0x008F` range.
3. **ClaimAnchor length when VP is absent:** The 504 B size is calculated using a 224 B EEA containing VP. P2 defines VP as optional, but the source does not clearly state whether P3 issuance MUST include VP or whether a no-VP layout is shorter.
4. **Example hash implementation:** The source example uses SHA3-256 instead of SM3 for demonstration. It is not a protocol implementation and MUST NOT be used as a conformance test vector.

This draft does not choose among the conflicting prefix or AttributeType assignments and does not change protocol constants. Resolve these issues in the authoritative baseline first, then synchronize this English edition.

---

*RFC-P3-001 ·* **GnomonSystem** *(Iris) Protocol · GnomonSystem Protocol Baseline v4.4 · English Version · 2026-10-20*
