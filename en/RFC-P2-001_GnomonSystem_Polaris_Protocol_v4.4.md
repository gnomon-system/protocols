# RFC-P2-001 — GnomonSystem (Polaris) Protocol v4.4

**GnomonSystem Protocol Baseline v4.4**

**V4.4 · 2026-09-11 · GNOMON BASELINE V4.4**  

---

## Abstract

This document defines the P2 layer of GnomonSystem: the Polaris Protocol.

Polaris addresses one core question: **How can the existence, timing, and causal relationships of any digital event be made non-forgeable, tamper-evident, and independently verifiable by any third party without disclosing business content?**

Core design:

- **EventAnchor core fields:** The Event Existence Anchor is the temporal foundation for all upper-layer proofs.
- **ChainProof:** A chained causal hash makes any insertion or deletion in history cryptographically detectable.
- **VerificationProof:** A recursive chained hash supports skip-based causal verification with O(1) complexity.
- **SemanticAnchor:** A general EEA interface for carrying the structural semantics of upper layers P3–P7; it is the cryptographic binding hub for events and subjects, content, authorization, relationships, and yield.
- **Semantic isolation:** L2 nodes store only cryptographic digests; no business plaintext passes through any node.

---

## Contents

Terms and notation

EEA data structure
2.1 EventAnchor core fields
2.2 VerificationProof (optional)
2.3 SemanticAnchor (optional)
2.4 ExtensionHeader (optional)
2.5 Field-construction order

ChainProof specification
3.1 Calculation
3.2 Chain-integrity verification
3.3 ChainProof security semantics
3.4 Timing and causality across L2 nodes

VerificationProof specification
4.1 Calculation
4.2 O(1) causal-verification algorithm (with checkpoint mechanism)

SemanticAnchor specification
5.1 Calculation (SM3 · 224 B)
5.2 Seventeen combination rules
5.3 Verification algorithm (with depth control)
5.4 Constraints within a layer

ExtensionHeader specification

L2 node behavior
7.1 EEA issuance flow
7.2 Collision detection
7.3 Pending-state management
7.4 Caching strategy

Revocation mechanism
8.1 RevocationRecord
8.2 Broadcast and propagation
8.3 Handling degraded EEAs

Verification specification
9.0 Self-contained verification boundary for an EEA
9.1 Verification depth
9.2 Full verification algorithm (pseudocode)
9.3 Full SemanticAnchor verification algorithm (pseudocode)

Protocol messages (Protobuf)

Security considerations

Test vectors

Error and warning codes

**V4.1 security revision: cluster replay protection**

Cluster requests MUST include the `x-cluster-nonce` field (an HTTP header). The receiver maintains a nonce cache with a 300-second TTL. A nonce that appears again during the cache period is rejected.

The nonce is not written into the fixed 192-byte EEA layout; it is only an HTTP-layer replay-protection mechanism. The cache uses LRU with a maximum of 100,000 entries.

**V4.2 protocol completion: fixed genesis values and Merkle convergence**

`VP_0` (genesis VerificationProof) and `ChainProof_root` (genesis ChainProof) are defined as fixed protocol constants; they cannot be negotiated or configured. See §§2.2 and 3.3 for their exact hexadecimal values.

The Merkle-tree convergence rules for a set of anchors across multiple nodes are defined in RFC-SEC-003 §5. Consistency checks for replication between P2 nodes MUST follow the SEC-003 Merkle-leaf formula and single-leaf rule.

Version history

---

## 1. Terms and notation

`H(·)` — SM3 hash function, 256-bit output, `𝔹* → 𝔹²⁵⁶`  
`Sign(sk, m)` — SM2 signature, returning a 512-bit signature `σ`  
`Verify(pk, m, σ)` — SM2 verification, returning `{0,1}`  
`BE64(n)` — 64-bit big-endian integer encoding, 8 bytes  
`BE32(n)` — 32-bit big-endian integer encoding, 4 bytes  
`BE16(n)` — 16-bit big-endian integer encoding, 2 bytes  
`∥` — byte-string concatenation  
`0ⁿ` — `n` zero bytes

`EEA` — Event Existence Anchor  
`AnchorID` — globally unique EEA identifier, 32 B, `H` of five fields  
`TI` — TemporalIndex, monotonically increasing `uint64` temporal value  
`ChainProof` — chained causal hash, 32 B  
`VerificationProof` — recursive chained hash, 32 B; abbreviated `VP`  
`SemanticAnchor` — structural semantic-binding hash, 32 B; abbreviated `SA`  
`ExtensionHeader` — fixed 8-byte subprotocol extension header (unified entry point, includes `reserved_flags`)

`L2 node` — a notary node that holds a KeyPackage and issues EEAs  
`origin_fingerprint` — `H` of the L2 node's SM2 public key, 32 B; abbreviated `OriginFP`  
`SequenceToken` — monotonically increasing sequence number within an L2 node, `uint64`; abbreviated `ST`

Domain-tag convention (`domain_tag`):

Prevents cross-protocol reuse of signatures at different layers.
The signing input at each layer begins with a unique ASCII byte string.
Polaris: `b"Polaris.Anchor.v1"` (17 bytes).

Dual-role convention for AnchorID (`FactID` · `AnchorID`):

| FactID (external reference identifier) | AnchorID (internal cryptographic identifier) |
|---|---|
| Transfer an event reference between organizations | Internal EEA field and signature verification |
| Embed in a business document (FactID annotation on an invoice) | ChainProof calculation input |
| Audit and reconciliation (look up an event by FactID) | Cross-layer reference (P3 ClaimAnchor → P2 EEA) |
| Transfer between network interfaces (lightweight · 32 B) | EEA issuance, verification, and synchronization |

They are the same 32-byte value but have different roles.
FactID is the external name for AnchorID. When an EEA's AnchorID is passed between organizations, embedded in a business document, or used as evidence for reconciliation, call it FactID to emphasize the semantic-isolation principle: “pass the identifier, not the content.”

Use across L2 nodes:

- Within the same L2 node: FactID supports ordering by TI value (guaranteed by monotonic TI).
- Across L2 nodes: FactID supports identity verification only (“this event was issued by a certain L2”); it does not support ordering. Ordering requires a ChainProof causal chain (see §3.4.2) or an independent external time source.

---

## 2. EEA data structure

### 2.1 EventAnchor core fields (fixed 192 B)

The base EEA structure consists of seven core fields. The offset and length of every field are fixed, and no field may be omitted.

| Offset | Length | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 32 B | `AnchorID` | `bytes[32]` | Calculation: `H("Polaris.Anchor.v1" ∥ BE64(TI) ∥ OriginFP ∥ BE64(ST) ∥ Salt)`. Meaning: globally unique, tamper-evident EEA identifier. Note: AnchorID does not depend on DigitalSignature, avoiding a circular dependency between the signature and AnchorID. |
| 32 | 8 B | `TemporalIndex` | `uint64` BE | Source: selected from the TI range assigned to the L2 node's current KeyPackage. Constraint: strictly increasing within one universe (monotonicity is not required after switching universes; ChainProof provides the order). `TI ∈ [ChildTHK.ti_range_start, ChildTHK.ti_range_end)`. Semantics: TI is an L1-authorized “temporal grid point” (traceable to a THK/RootTHK time window), not a wall-clock reading for each transaction; do not describe it externally as an “exact microsecond birth time.” |
| 40 | 32 B | `OriginFingerprint` | `bytes[32]` | Calculation: `H(L2_node_SM2_public_key_bytes)`. Meaning: cryptographic identifier of the L2 node that issued this EEA. Invariant: all EEAs from the same node have the same OriginFP. |
| 72 | 8 B | `SequenceToken` | `uint64` BE | Rule: strictly increasing under the same OriginFP, starting at 1. It does not reset on restart (persist it; see §7.1) or when switching L1s (continuous for the lifetime of the node; see §7.2). Increment by 1 for each issued EEA. |
| 80 | 32 B | `ChainProof` | `bytes[32]` | Calculation: see §3.1. Meaning: cryptographic causal link to the preceding EEA. |
| 112 | 64 B | `DigitalSignature` | `bytes[64]` | Calculation: `Sign(sk_L2, e)`, where `e = SM3(signing_payload)` is the pre-digest and the no-ZA-prehash path is used (see §2.1.1 for `signing_payload`). |
| 176 | 16 B | `Salt` | `bytes[16]` | Calculation: generated by a CSPRNG. Meaning: random salt for AnchorID, preventing predictable AnchorIDs when identical TI/ST combinations occur during abnormal recovery. Constraint: MUST be generated by a cryptographically secure random-number generator and MUST be persisted and synchronized with the EEA. Semantics: Salt is a random salt for prediction resistance/recovery and carries no business semantics (it does not answer “when / who / which transaction number”). The primary contributions to AnchorID uniqueness are an ST that is never reused within a node, OriginFP, and TI; Salt supplies fallback entropy. |
| **Total** | **192 B** |  |  |  |

#### 2.1.1 DigitalSignature signing input (137 B)

```text
signing_payload =
    b"Polaris.Anchor.v1" (17 B) domain_tag (prevents cross-protocol reuse)
    ∥ AnchorID (32 B) (binds AnchorID and prevents AnchorID replacement)
    ∥ BE64(TemporalIndex) (8 B)
    ∥ OriginFingerprint (32 B)
    ∥ BE64(SequenceToken) (8 B)
    ∥ ChainProof (32 B)
    ∥ BE32(key_version) (4 B) (version of the node signing public key)
    ∥ degraded_mode (1 B) (0x00 = normal window; 0x01 = KeyPackage grace window)
    ∥ reserved_future (3 B) MUST=0; aggregated with key_version + degraded_mode into an 8-byte control block
total = 17+32+8+32+8+32+4+1+3 = 137 B

e = SM3(signing_payload)
DigitalSignature = Sign(sk_L2, e)
```

**Signature semantics (MUST):** `e = SM3(signing_payload)` is the SM2 pre-digest. Signing uses the **no-ZA-prehash path**: SM2 does not compute ZA (the signer identity) internally and does not apply SM3 a second time (see FMD definition 0.0). The signing nonce `k` follows RFC-SEC-002 §2 (RFC 6979 or a 256-bit CSPRNG value).

Verification:

```text
Verify(pk_L2, e, DigitalSignature) == 1
```

### 2.2 VerificationProof (32 B, MAY)

VerificationProof is optional and is appended after the core fields.
Position: after the 192-byte EEA core.  
Length: fixed at 32 B when present.

**Calculation:**

```text
VP_n = H(AnchorID_(n-1) ∥ VP_(n-1))
```

The `VP_0` of the first EEA (with no predecessor) MUST be the following fixed protocol constant; it cannot be negotiated or configured:

```text
VP_0 = SM3(0x00 × 64)
     = 46b58571be41685c253194d20ec7f82b659cc8c6b753f26d4e9ec85bc91c231e
```

If the preceding EEA has no VP field:

```text
VP_n = H(AnchorID_(n-1) ∥ 0³²)
```

Use all zeros in place of the preceding VP.

**Presence rules:**

- If an L2 node supports VP (recommended; SHOULD), every EEA MUST include the VP field.
- Partial inclusion is prohibited (within one node chain, either all EEAs include it or none do).
- VP continuity is not required for cross-node references.

### 2.3 SemanticAnchor (32 B, MAY)

SemanticAnchor is the core connection hub through which an EEA carries the structural semantics of upper layers. It is appended after VP, if VP is present, or after the core fields otherwise.
Position: after the VP field, if present, or after the core fields.  
Length: fixed at 32 B when present.  
All-zero value: `0³²` means an anonymous event and skips verification.

**Calculation (SM3 · fixed 224-byte input):**

```text
SA = H(
    AnchorID (32 B) (binds SA to this specific EEA and prevents cross-EEA transplant attacks)
    ∥ P3_ref (32 B) ClaimAnchor.AnchorID or 0³²
    ∥ P4_ref (32 B) ScrollAnchor.AnchorID or 0³²
    ∥ P5_ref (32 B) GrantAnchor.AnchorID or 0³²
    ∥ P6_ref (32 B) BondAnchor.AnchorID or 0³²
    ∥ P7_ref (32 B) YieldAnchor.AnchorID or 0³²
    ∥ event_data_hash (32 B) H(canonical serialized bytes of the business data)
)
Input length: 7 × 32 B = 224 B (fixed)
```

**Key design: embedding AnchorID**

AnchorID is embedded in the SA calculation input. Therefore, identical `{P3_ref..P7_ref, event_data_hash}` parameters produce different SAs for different EEAs, preventing cross-EEA transplant attacks (T10).

See §5 for the full specification.

### 2.4 ExtensionHeader (8 B, MAY)

| Offset | Length | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 2 B | `extension_type` | `uint16` BE | Subprotocol type code |
| 2 | 1 B | `version` | `uint8` | Starts at 1 and increases monotonically |
| 3 | 1 B | `hdr_flags` | `uint8` | bit0: `critical` (0 = may ignore; 1 = must reject); bit1: `chain_follows` (extension chain is related); bit2: `payload_present` (0 = signal only; 1 = includes payload); bits3–7: `reserved_future` (MUST=0) |
| 4 | 2 B | `length` | `uint16` BE | Number of payload bytes |
| 6 | 1 B | `compliance` | `uint8` | 0 = no alignment declared; 1 = uint64 / 8-byte alignment · Decisions 017/019; 2–255 = reserved |
| 7 | 1 B | `reserved_future` | `uint8` | MUST=0; reserved for `hdr_flags` / `compliance` expansion |
| **Total** | **8 B** | **header** |  | **payload: `length` bytes** |

The payload (`length` bytes) immediately follows ExtensionHeader. Multiple ExtensionHeaders may appear consecutively.

**Protocol version identifier:** `ExtHeader.version` (at EEA offset 194; fixed) is the sole authoritative protocol-version identifier.
After reading an EEA, a parser immediately locates ExtHeader → byte[2] → version number; it does not need to search the signing input for `domain_tag`.
This design uses “fixed-offset parsing,” like NTP byte[0], rather than the “addressing within the signature” pattern used by `domain_tag`.
Making versions explicit for P1 structures such as TI / KeyPackage is deferred to V5.0.

**Registered `extension_type` values (P2 layer):**

| Value | Name | Description |
|---|---|---|
| `0x0011` | `DegradedModeRecord` | Degraded-mode record |
| `0x0012` | `KeyRevocationRecord` | Root-key revocation record |
| `0x0101` | `FinancialEEA` | Financial-settlement event |
| `0x0201` | `GovEEA` | Government-coordination event |
| `0x0311` | `JudicialEEA` | Judicial evidence event |

### 2.4.1 Extension alignment convention

The ExtHeader structure is fixed at 8 B (MUST), ensuring a unified, parseable extension entry point.
Subextension payloads SHOULD be aligned to 8-byte boundaries (uint64 values land on 8-byte boundaries).
Implementers MUST handle unaligned memory access themselves for unaligned subextensions.

New subextensions are RECOMMENDED to follow the full field-reordering principle to obtain zero-copy performance equivalent to the main structure.
Payloads of existing subextensions such as MultiSignScroll (`0x0402`) and RelationTransfer (`0x0604`) are not required to use the full reordering; implementations handle them at the implementation layer under this convention.

### 2.5 Field-construction order

The EEA fields depend on one another and MUST be calculated in the following order:

Step 1: Obtain TI from the KeyPackage (a currently available TI) and increment SequenceToken.  
Step 2: Calculate ChainProof (depends on the preceding EEA; see §3.1).  
Step 3: Generate Salt (16 B from a CSPRNG).  
Step 4: Calculate `AnchorID = H("Polaris.Anchor.v1" ∥ BE64(TI) ∥ OriginFP ∥ BE64(ST) ∥ Salt)`.  
Step 5: Construct `signing_payload` and generate DigitalSignature.  
Step 6: Calculate VerificationProof (optional; depends on the preceding VP and preceding AnchorID).  
Step 7: Calculate SemanticAnchor (optional; depends on AnchorID and P3–P7 reference parameters).  
Step 8: Assemble ExtensionHeader (optional).  
Step 9: Write the complete EEA to local storage and return AnchorID.

*Note: DigitalSignature covers AnchorID and ChainProof, but DigitalSignature itself is not used to calculate AnchorID. This structure avoids the circular dependency in which “AnchorID depends on the signature, while the signature also covers AnchorID,” while retaining complete signature protection for the chain proof and temporal fields.*

---

## 3. ChainProof specification

### 3.1 Calculation

**Standard ChainProof (with a preceding EEA):**

```text
ChainProof_n = H(
    AnchorID_(n-1) (32 B) preceding EEA's AnchorID
    ∥ BE64(TI_(n-1)) (8 B) preceding EEA's TemporalIndex
    ∥ DigitalSignature_(n-1) (64 B) preceding EEA's signature
)
Total input: 104 B
```

**The ChainProof of the root EEA (no predecessor) MUST be the following fixed protocol constant; it cannot be negotiated or configured:**

```text
ChainProof_root = SM3(0x00 × 104)   // 32 B AnchorID + 8 B TI + 64 B signature, all zero
                = 76693c862ce3571fba1a986ea58f58c645464d2469c28f197fa85db54dac4103
```

**Cross-node ChainProof:**

If the EEA chain of L2 node A uses an EEA from node B as its predecessor (a cross-node causal reference), ChainProof is calculated in the same way, using the field values from node B's EEA.

### 3.2 Chain-integrity verification algorithm

```python
def verify_chain(eeas: list[EEA]) -> tuple[bool, str]:
    """Verify the integrity of an EEA chain.
    eeas: list of EEAs ordered by ascending TI
    returns: (is_valid, error_message)

    Note: This algorithm requires the complete, contiguous EEA sequence. If
    only the first and last EEAs are available, use VerificationProof for O(1)
    causal verification (see §4.2).
    """
    if not eeas:
        return True, ""

    for i, eea in enumerate(eeas):
        # 1. Verify AnchorID (formula in §2.1.1 Step 4: includes domain_tag and
        #    Salt, but not ChainProof or signature, to avoid circular dependency)
        expected_anchor_id = H(
            b"Polaris.Anchor.v1"
            + BE64(eea.temporal_index)
            + eea.origin_fingerprint
            + BE64(eea.sequence_token)
            + eea.salt
        )
        if eea.anchor_id != expected_anchor_id:
            return False, f"E001: AnchorID mismatch at position {i}"

        # 2. Verify DigitalSignature
        signing_payload = (
            b"Polaris.Anchor.v1"
            + eea.anchor_id
            + BE64(eea.temporal_index)
            + eea.origin_fingerprint
            + BE64(eea.sequence_token)
            + eea.chain_proof
            + BE32(eea.key_version)
            + bytes([eea.degraded_mode])
            + bytes(3)  # reserved_future: 3 B, MUST=0; aggregated with key_version + degraded_mode into an 8-byte control block
        )
        pk_l2 = get_node_pubkey(eea.origin_fingerprint)  # query the node registry
        if not Verify(pk_l2, SM3(signing_payload), eea.digital_signature):
            return False, f"E002: DigitalSignature invalid at position {i}"

        # 3. Verify ChainProof
        if i == 0:
            # Root EEA: ChainProof = H(0 × 104)
            expected_cp = H(bytes(104))
        else:
            prev = eeas[i - 1]
            expected_cp = H(
                prev.anchor_id
                + BE64(prev.temporal_index)
                + prev.digital_signature
            )
        if eea.chain_proof != expected_cp:
            return False, f"E003: ChainProof mismatch at position {i}"

        # 4. Verify monotonic TI (within the same universe; skip after a
        #    cross-universe switch)
        if i > 0 and eeas[i-1].origin_fingerprint == eea.origin_fingerprint:
            # Same-universe determination: the EEA itself has no universe field;
            # the verifier traces the issuer through KeyPackage → ChildTHK → RootTHK.
            if universe_of(eeas[i-1]) == universe_of(eea):
                if eea.temporal_index <= eeas[i-1].temporal_index:
                    return False, f"E004: TI is not monotonically increasing at position {i}"
            # On a cross-universe switch (different issuer), TI may move backward;
            # ChainProof provides the ordering link.

        # 5. Verify monotonic SequenceToken (within the same OriginFP)
        if i > 0 and eeas[i-1].origin_fingerprint == eea.origin_fingerprint:
            if eea.sequence_token <= eeas[i-1].sequence_token:
                return False, f"E005: SequenceToken is not monotonically increasing at position {i}"

    return True, ""
```

### 3.3 ChainProof security semantics

**Defense against insertion:**

If an attacker inserts a fake EEA `E_fake` at position `k`:

```text
E_fake.chain_proof = H(E_(k-1).anchor_id ∥ ...)  // can be calculated correctly
E_k.chain_proof    = H(E_(k-1).anchor_id ∥ ...)  // original value remains unchanged
but E_k.chain_proof ≠ H(E_fake.anchor_id ∥ ...)
→ ChainProof verification fails for every entry after position k → insertion is detected
```

**Defense against deletion:**

If an attacker deletes the EEA at position `k`:

```text
E_(k+1).chain_proof = H(E_k.anchor_id ∥ ...)
E_(k-1) is now treated as the “predecessor”
H(E_(k-1).anchor_id ∥ ...) ≠ E_(k+1).chain_proof
→ deletion is detected
```

**Defense against replacement:**

If an attacker replaces `E_k` with `E_k'` (changing any field):

```text
E_k'.anchor_id ≠ E_k.anchor_id
    (AnchorID = H(domain_tag ∥ TI ∥ OriginFingerprint ∥ SequenceToken ∥ Salt))
E_(k+1).chain_proof ≠ H(E_k'.anchor_id ∥ ...)
→ replacement is detected
```

### 3.4 Timing and causality across L2 nodes

This section answers a core implementation question: multiple L2 nodes under the same L1 node maintain their EEA chains independently; how are timing and causal relationships between those chains determined?

#### 3.4.1 TI uniqueness is guaranteed by L1 range allocation

TI (TemporalIndex) is not calculated by L2 nodes from local clocks. The L1 node allocates **non-overlapping** TI ranges through KeyPackages.

The L1 assigns an independent TI range to each L2 node, for example:

```text
L2 node A: ChildTHK.ti_range ∈ [t_a_start, t_a_end)
L2 node B: ChildTHK.ti_range ∈ [t_b_start, t_b_end)
The ranges do not overlap.
```

When issuing an EEA, an L2 node can use only the TI allocation range (`ti_range_start`–`ti_range_end`) of the ChildTHK carried by that node.
SequenceToken remains monotonically increasing for the lifetime of the node (it is not reset when switching L1s), guaranteeing unique AnchorIDs under the same OriginFP; overlapping TI values across universes are distinguished by ST (see the collision key in §7.2).

→ When two L2 nodes sign EEAs at the **same physical moment**, they use values from their respective TI ranges; TI is globally unique and never conflicts.

Key principle: global uniqueness of TI results from L1 range allocation and does not depend on the precision or consistency of L2 nodes' local clocks. The local L2 clock is used only to select a value within the authorized TI range and does not participate in the uniqueness guarantee.

#### 3.4.2 Concurrent events without a causal link: no order is defined

If two L2 nodes' EEAs do **not reference one another** (there is no ChainProof causal link), their relative order **is undefined**, and the system does not need to define it.

This is how the causal-universe model appears within an L1 domain (see P1 RFC §1 terminology, §2.7 TI comparability, and §4 causal-universe boundaries):

Events within one L1 domain form a partial order, not a total order.
Only events with a causal link have meaningful ordering.

Design rationale:

Requiring a total order for every pair of concurrent, unrelated events is equivalent to requiring global consensus, which would add synchronization overhead contrary to the causal-universe model.
Gnomon does not pursue a total order; the relative order of events with no causal relationship does not need arbitration.

Implementation implications:

It is entirely valid for L2 nodes A and B to sign mutually unreferenced EEAs concurrently.
An implementation need not, and SHOULD NOT, attempt to determine “which happened first.”

#### 3.4.3 Causal references across L2 nodes

When an event at L2 node A causally depends on event `E_B` at L2 node B, establish a causal link through cross-node ChainProof:

Procedure:

1. Through a node-to-node synchronization mechanism, L2 node A obtains `E_B` as needed (actively fetch the target EEA; do not broadcast all EEAs globally in real time).
2. A constructs a new EEA `E_A` whose ChainProof references `E_B`:

   ```text
   E_A.chain_proof = H(E_B.anchor_id ∥ E_B.TI ∥ E_B.digital_signature)
   ```

3. Within the same L2 node, `E_B.TI < E_A.TI` holds (ChildTHK range order and monotonically increasing TI). A cross-L2 reference guarantees causal order only; it does not guarantee the numeric relationship between TI values. If a physical-time reference is needed, obtain it independently from the National Time Service Center through its protocol; do not rely on internal `t_utc`. This keeps the proof chain separate from the time-reference information.

Timing guarantee:

A cross-node reference naturally satisfies causal timing: the referenced event (`E_B`) must exist before the referencing event (`E_A`) can be signed; the reference itself encodes the causal fact “E_B precedes E_A.”

Verification:

Using the public key of the **same L1 node**, a verifier can verify both parties' signatures and E_A's ChainProof reference to E_B, without any additional cross-node trust assumption.

#### 3.4.4 L2 nodes under the same L1 do not need mutual recognition

L2 nodes under the same L1 node **do not need** to establish mutual recognition (they do not use CSR).

Reasons:

- They share the same L1 trust root; a verifier can use the same L1 public key to verify every L2 EEA.
- All TI ranges are allocated by the same L1 and are naturally comparable.
- Cross-node causal references (§3.4.3) are sufficient to express causality between L2 nodes.

CSR (CrossDomainContactRecord; see RFC-TIANSHU) is used only to establish a contact surface between **different L1 nodes** (different causal universes).
CSR is unnecessary within the same L1 domain.

#### 3.4.5 Implementation summary

- TI uniqueness ← L1 range allocation, not the L2 local clock.
- Concurrent, unrelated events ← no order is defined (partial order).
- Causal dependency ← fetch the preceding EEA as needed + cross-node ChainProof.
- Within the same L1 domain ← no L2 mutual recognition and no CSR needed.
- Cross-node verification ← the same L1 public key is sufficient.

## 4. VerificationProof specification

### 4.1 Calculation

```text
VP_n = H(AnchorID_(n-1) ∥ VP_(n-1))
```

Recursive expansion:

```text
VP_0 = 46b58571be41685c253194d20ec7f82b659cc8c6b753f26d4e9ec85bc91c231e  (fixed protocol constant; see §2.2)
VP_1 = H(AnchorID_0 ∥ VP_0)
VP_2 = H(AnchorID_1 ∥ VP_1)
     = H(AnchorID_1 ∥ H(AnchorID_0 ∥ VP_0))
VP_n = H(AnchorID_(n-1) ∥ H(AnchorID_(n-2) ∥ ... H(AnchorID_0 ∥ VP_0)...))
```

VP is a cumulative hash of the AnchorID sequence. It resembles a Merkle chain but does not support random-access proofs.

### 4.2 O(1) causal-verification algorithm (with checkpoint mechanism)

Problem: prove that `EEA_i` precedes `EEA_j` (`i < j`) without traversing the intermediate nodes.

Checkpoint mechanism:

To achieve genuinely O(1) verification, an L2 node SHOULD generate a VP checkpoint every 1,000 EEAs.
The checkpoint value (the current VP) is written to the EEA's ExtensionHeader (`extension_type = 0x0013`) or directly to that EEA's `verification_proof` field (if VP is supported).

Algorithm:

```python
def verify_causality_o1(
    eea_i: EEA,   # earlier EEA (claimed to precede)
    eea_j: EEA,   # later EEA (claimed to follow)
    checkpoints: list[tuple[bytes, bytes]],  # [(AnchorID, VP)] sparse checkpoints
) -> tuple[bool, str]:
    """O(1) causal verification: prove that eea_i precedes eea_j.

    Use checkpoints (one per 1,000 EEAs) for skip verification.
    Verification steps ≈ (j-i)/1000 and can be treated as constant in practice.
    """
    if eea_i.temporal_index >= eea_j.temporal_index:
        return False, "E006: incorrect TI order"

    if eea_i.verification_proof is None or eea_j.verification_proof is None:
        # Fall back to ChainProof traversal (O(n))
        return False, "VP support or the complete intermediate sequence is required"

    # Start from eea_i.VP and skip to the nearest checkpoint
    current_vp = eea_i.verification_proof
    current_anchor = eea_i.anchor_id

    # Skip using checkpoints (assume they are ordered by time)
    for anchor_id, vp in checkpoints:
        # Verify checkpoint VP consistency
        expected_vp = H(current_anchor + current_vp)
        if vp != expected_vp:
            return False, "E007: checkpoint VP verification failed"
        current_vp = vp
        current_anchor = anchor_id

    # Final check: eea_j.VP should equal H(preceding AnchorID of eea_j ∥ cumulative VP)
    # Assume the preceding AnchorID of eea_j is the last checkpoint or can be obtained another way.
    prev_anchor_of_j = get_prev_anchor(eea_j.anchor_id)  # must be supplied or obtained from the chain
    expected_vp_j = H(prev_anchor_of_j + current_vp)
    if eea_j.verification_proof != expected_vp_j:
        return False, "E008: VerificationProof verification failed; causal relationship not established"

    return True, ""

# Simplified: if it is known that both are in the same node chain and their direct predecessor is provided
def verify_direct_causality(eea_i: EEA, eea_j: EEA, prev_anchor_of_j: bytes) -> bool:
    """Directly verify whether eea_j.VP is causally associated with eea_i.
    The direct preceding AnchorID of eea_j must be provided.
    """
    expected_vp = H(prev_anchor_of_j + eea_i.verification_proof)
    return eea_j.verification_proof == expected_vp
```

Applicable scenarios:

Audit scenario: verify that “all events in a batch existed before time T.”
→ Provide the first and last VPs of the batch and intermediate checkpoints; verify in O(1).

Cross-domain reference: Universe B references the temporal position of an EEA in Universe A.
→ VP provides a compact temporal proof without transferring the complete chain.

Judicial scenario: prove that “contract signing (E_sign) preceded the dispute (E_dispute).”
→ VP plus checkpoints is sufficient.

## 5. SemanticAnchor specification

### 5.1 Calculation

```python
ZERO_32 = b'\x00' * 32

def compute_semantic_anchor(
    eea_anchor_id:   bytes,           # EEA.AnchorID, 32 B, MUST
    p3_ref:          bytes = ZERO_32, # ClaimAnchor.AnchorID or all zeros
    p4_ref:          bytes = ZERO_32, # ScrollAnchor.AnchorID or all zeros
    p5_ref:          bytes = ZERO_32, # GrantAnchor.AnchorID or all zeros
    p6_ref:          bytes = ZERO_32, # BondAnchor.AnchorID or all zeros
    p7_ref:          bytes = ZERO_32, # YieldAnchor.AnchorID or all zeros
    event_data_hash: bytes = ZERO_32, # H(business data), 32 B
) -> bytes:
    """Compute SemanticAnchor. Input is fixed at 224 B; output is 32 B."""
    inputs = [eea_anchor_id, p3_ref, p4_ref, p5_ref,
              p6_ref, p7_ref, event_data_hash]
    assert all(len(x) == 32 for x in inputs), "Every input must be 32 B"
    payload = b"".join(inputs)
    assert len(payload) == 224
    return H(payload)
```

Version control:

`SA_version = 1` (current):

- Algorithm: `SM3(224 B)`.
- Includes: AnchorID + five layer references + `event_data_hash`.

`SA_version = 2` (reserved · post-quantum):

- Algorithm: `PostQuantumHash(224 B)` (to be defined after a national cryptography authority standard is published).
- Input structure is unchanged (224 B); only the hash algorithm is replaced.

Version identifier: passed through the `SemanticAnchorInput.version` field.  
Historical compatibility: records with `SA_version=1` remain valid permanently (time-cut principle).

### 5.2 Seventeen combination rules

Complete rules for layer combinations:

Single layer (2 meaningful combinations):

```text
[P3] SM3(AnchorID ∥ P3 ∥ 0³² ∥ 0³² ∥ 0³² ∥ 0³² ∥ event)
     Meaning: an action by a subject
[P4] SM3(AnchorID ∥ 0³² ∥ P4 ∥ 0³² ∥ 0³² ∥ 0³² ∥ event)
     Meaning: existence of content (anonymous)
```

Two layers (5 combinations):

| Combination | Meaning |
|---|---|
| `[P3+P4]` | A subject created some content |
| `[P3+P5]` | A subject performed an operation under an authorization |
| `[P3+P6]` | A subject acted within a relationship |
| `[P3+P7]` | A subject received yield |
| `[P5+P7]` | Yield was generated under an authorization (less common) |

Three layers (5 combinations):

| Combination | Meaning |
|---|---|
| `[P3+P4+P5]` | A subject created content under authorization |
| `[P3+P5+P6]` | A subject performed an operation based on a relationship and authorization |
| `[P3+P4+P7]` | A subject created content and benefited from it (copyright) |
| `[P3+P5+P7]` | A subject performed an authorized operation and received yield |
| `[P3+P6+P7]` | A subject received yield based on a relationship |

Four layers (4 combinations):

| Combination | Meaning |
|---|---|
| `[P3+P4+P5+P6]` | Complete operation (without yield) |
| `[P3+P4+P5+P7]` | Authorized content + yield |
| `[P3+P5+P6+P7]` | Relationship + authorization + yield |
| `[P3+P4+P6+P7]` | Relationship + content + yield |

Five layers (all layers; 1 combination):

`[P3+P4+P5+P6+P7]` — a complete collaborative fact.

Special (all zeros):

`[none]` — `SA = 0³²` (anonymous event; no upper-layer semantics are bound).

### 5.3 Full SA verification algorithm

```python
def verify_semantic_anchor(
    eea:            EEA,
    sa_input:       SemanticAnchorInput,
    verify_depth:   int = 3,  # 1=minimal, 2=standard, 3=full
) -> VerifyResult:
    """Verify the SemanticAnchor of an EEA.
    Returns a VerifyResult containing the verification result for each layer.

    Note: The verifier MUST obtain sa_input parameters from the business system
    or a trusted source; these parameters are not stored on L2 nodes.
    """
    result = VerifyResult()

    # Step 1: Check the special value
    if eea.semantic_anchor == ZERO_32:
        result.valid = True
        result.note = "Anonymous event; no semantic binding"
        return result

    # Step 2: Reconstruct and verify (SM3 · 224 B)
    computed_sa = compute_semantic_anchor(
        eea_anchor_id   = eea.anchor_id,
        p3_ref          = sa_input.p3_ref,
        p4_ref          = sa_input.p4_ref,
        p5_ref          = sa_input.p5_ref,
        p6_ref          = sa_input.p6_ref,
        p7_ref          = sa_input.p7_ref,
        event_data_hash = sa_input.event_data_hash,
    )
    if computed_sa != eea.semantic_anchor:
        return VerifyResult(valid=False, error=E030)

    # Step 3: Check existence and type of each layer anchor (query in parallel)
    layer_checks = {
        3: (sa_input.p3_ref, 0x0102, "ClaimAnchor"),
        4: (sa_input.p4_ref, 0x0401, "ScrollAnchor"),
        5: (sa_input.p5_ref, 0x0501, "GrantAnchor"),
        6: (sa_input.p6_ref, 0x0601, "BondAnchor"),
        7: (sa_input.p7_ref, 0x0701, "YieldAnchor"),
    }

    for layer, (ref, expected_ext_type, name) in layer_checks.items():
        if ref == ZERO_32:
            continue  # this layer was not referenced; skip it

        # Query L2 node storage
        anchor = query_anchor(ref)
        if anchor is None:
            result.add_error(layer, E031, f"{name} does not exist")
            continue

        # Type check: Anchor extension_type must match the layer
        if anchor.extension_type != expected_ext_type:
            result.add_error(layer, E034, f"Type mismatch: expected {expected_ext_type:#06x}")
            continue

        # Validity check (using EEA.TI as the time basis)
        ref_ti = eea.temporal_index
        if not is_valid_at_ti(anchor, ref_ti):
            result.add_error(layer, E032, f"{name} was invalid at TI={ref_ti}")
            continue

        result.add_layer_valid(layer, ref)

    # If verify_depth < 3, verify only the required layers
    if verify_depth == 1:
        # minimal: do not verify SA references
        result.clear_layer_errors()

    # Step 4: Check layer-level constraints (SHOULD level)
    if sa_input.p3_ref != ZERO_32 and sa_input.p4_ref != ZERO_32:
        scroll = query_anchor(sa_input.p4_ref)
        if scroll and scroll.claim_anchor_ref != sa_input.p3_ref:
            result.add_warning(W010, "P4.ClaimAnchorRef does not match P3_ref")

    if sa_input.p3_ref != ZERO_32 and sa_input.p5_ref != ZERO_32:
        grant = query_anchor(sa_input.p5_ref)
        if grant:
            p3_anchor = query_anchor(sa_input.p3_ref)
            if p3_anchor and grant.grantee_fingerprint != p3_anchor.entity_fingerprint:
                result.add_warning(W010, "P5.GranteeFingerprint does not match P3.EntityFingerprint")

    if sa_input.p3_ref != ZERO_32 and sa_input.p6_ref != ZERO_32:
        bond = query_anchor(sa_input.p6_ref)
        if bond:
            p3_anchor = query_anchor(sa_input.p3_ref)
            if p3_anchor:
                fp = p3_anchor.entity_fingerprint
                if fp not in (bond.subject_a_fingerprint, bond.subject_b_fingerprint):
                    result.add_warning(W010, "P3 subject is not one of the parties in the P6 relationship")

    # Step 5: Verify event_data_hash
    if sa_input.event_data_hash != ZERO_32:
        if sa_input.event_data_hash != H(sa_input.raw_event_data):
            result.add_error(0, E033, "event_data_hash mismatch")

    result.valid = not result.has_errors()
    return result
```

### 5.4 Constraints within a layer (SHOULD)

Constraint 1 (P3 + P4):

`ScrollAnchor.ClaimAnchorRef SHOULD == P3_ref`  
Meaning: the creator of the content SHOULD be the same as the subject of the event.

Constraint 2 (P3 + P5):

`GrantAnchor.GranteeFingerprint SHOULD == P3_anchor.EntityFingerprint`  
Meaning: the grantee of the authorization SHOULD be the same as the subject of the event.

Constraint 3 (P3 + P6):

`P3_anchor.EntityFingerprint SHOULD ∈ {BondAnchor.SubjectAFP, SubjectBFP}`  
Meaning: the subject of the event SHOULD be one of the parties in the relationship.

Constraint 4 (when P7 is present):

`YieldAnchor.BeneficiaryClaimRef SHOULD == P3_ref`  
Meaning: the beneficiary SHOULD be the same as the subject of the event.

All of the above are SHOULD (recommended), not MUST (mandatory).
On violation, return W010; do not reject the EEA.
Reasonable exceptions: agency scenarios, multi-party events, and delegated execution.

## 6. ExtensionHeader specification

Processing rules:

```python
def process_extensions(eea_bytes: bytes, offset: int) -> list[Extension]:
    """Parse the sequence of extension headers at the end of an EEA."""
    extensions = []
    while offset < len(eea_bytes):
        if offset + 8 > len(eea_bytes):          # ExtHeader = 8 B
            raise ParseError(E_TRUNCATED)

        ext_type   = int.from_bytes(eea_bytes[offset:offset+2], 'big')
        version    = eea_bytes[offset+2]
        hdr_flags  = eea_bytes[offset+3]
        critical   = hdr_flags & 0x01            # bit 0
        length     = int.from_bytes(eea_bytes[offset+4:offset+6], 'big')

        payload = eea_bytes[offset+8 : offset+8+length]
        if len(payload) != length:
            raise ParseError(E_TRUNCATED)

        if ext_type not in KNOWN_EXTENSION_TYPES:
            if critical:
                raise UnsupportedExtension(ext_type)
            # critical=0: ignore the unknown extension and continue processing
        else:
            extensions.append(Extension(ext_type, version, payload))

        offset += 8 + length                     # ExtHeader = 8 B

    return extensions
```

Backward-compatibility rules:

`hdr_flags.bit0 = 0` (critical flag not set):

- A node that does not recognize this extension type may ignore it and continue processing the EEA.
- Applicable to optional enhancements (such as VP · performance optimization).

`hdr_flags.bit0 = 1` (critical):

- A node that does not recognize this extension type MUST reject the entire EEA.
- Return `E_CRITICAL_UNKNOWN` (unsupported extension type).
- Applicable to protocol-mandatory features (such as the ClaimAnchor identity extension).

## 7. L2 node behavior

### 7.1 EEA issuance flow

```python
def sign_eea(
    event_data_hash:  bytes,       # H(business data), supplied by the business system
    semantic_input:   SemanticAnchorInput | None,
    extension_payload: bytes | None,
) -> EEA:
    """Complete flow for an L2 node to issue an EEA."""

    # Step 1: Check KeyPackage validity
    kp = get_current_key_package()
    if not is_valid(kp):
        raise KeyPackageExpired()
    node_key_version = get_current_node_key_version(origin_fingerprint)

    # Step 2: Allocate TI and ST atomically to prevent races
    with ti_lock:
        ti = allocate_next_ti(kp)         # obtain the next value in the KP TI range
        st = increment_sequence_token()    # globally monotonic and stored persistently
        # SequenceToken must be persisted to disk and restored after node restart
        # to prevent reuse of the same sequence number after restart.

    # Step 3: Get preceding EEA information
    prev = get_last_eea()  # latest EEA from this node
    chain_proof = compute_chain_proof(prev)
    degraded_mode = 1 if in_keypackage_grace_window(kp, ti) else 0

    # Step 4: Generate Salt and calculate AnchorID (independent of the signature)
    salt = csprng(16)
    anchor_id = H(
        b"Polaris.Anchor.v1"
        + BE64(ti)
        + origin_fingerprint
        + BE64(st)
        + salt
    )

    # Step 5: Calculate DigitalSignature
    signing_payload = (
        b"Polaris.Anchor.v1"
        + anchor_id
        + BE64(ti)
        + origin_fingerprint
        + BE64(st)
        + chain_proof
        + BE32(node_key_version)
        + bytes([degraded_mode])
        + bytes(3)  # reserved_future: 3 B, MUST=0
    )
    digital_sig = hsm_sign(sk_l2, SM3(signing_payload))  # HSM signature (prehash: pass e = SM3(original input))

    # Step 6: Calculate VerificationProof (optional)
    vp = compute_verification_proof(prev.anchor_id, prev.vp) if prev else None

    # Step 7: Calculate SemanticAnchor (optional)
    sa = None
    if semantic_input:
        sa = compute_semantic_anchor(
            eea_anchor_id   = anchor_id,
            p3_ref          = semantic_input.p3_ref,
            p4_ref          = semantic_input.p4_ref,
            p5_ref          = semantic_input.p5_ref,
            p6_ref          = semantic_input.p6_ref,
            p7_ref          = semantic_input.p7_ref,
            event_data_hash = semantic_input.event_data_hash,
        )

    # Step 9: Write to local storage
    eea = EEA(
        anchor_id          = anchor_id,
        temporal_index     = ti,
        origin_fingerprint = origin_fingerprint,
        sequence_token     = st,
        chain_proof        = chain_proof,
        digital_signature  = digital_sig,
        verification_proof = vp,
        semantic_anchor    = sa,
        key_version        = node_key_version,
        degraded_mode      = degraded_mode,
    )
    store.write(eea)

    # Step 10: Update collision-detection index
    collision_index.add(ti, st, anchor_id)

    return eea
```

### 7.2 Collision detection

Rule: under the same L2 node (`OriginFP`), a `(TI, ST)` pair may be used by only one EEA.
TI may overlap across universes (partial order; see P1 §4), while ST is continuous for the lifetime of a node and is not reset when changing L1. Together they guarantee unique AnchorIDs. The collision key is `(OriginFP, TI, ST)`, not `(OriginFP, TI)`.

Semantics (responsibility): collision detection protects against AnchorID collisions (that is, accidental reuse of ST); it does not prevent TI reuse.
TI may overlap across universes (partial order), and multiple events may use the same TI within one universe (distinguished by ST). AnchorID uniqueness is guaranteed by the tuple `(TI, OriginFP, ST, Salt)`, where never reusing ST is the key.
Therefore, collision detection is a “safety net,” not business logic: it should not normally trigger (ST is never reused), and triggers only if ST persistence fails or rolls back and causes a real AnchorID collision.
Collision detection does not establish a separate “ST primary key”: the storage primary key and external reference (FactID) are always AnchorID; ST is only one field in AnchorID.

```python
def detect_collision(ti: int, origin_fp: bytes, st: int) -> bool:
    """Check whether (TI, ST) has already been used under the same OriginFP.
    Returns True if a collision exists; False if it is safe.
    """
    # Layer 1: Bloom Filter (in memory, <1 μs, 0.01% false-positive rate)
    if not bloom_filter.possibly_contains(origin_fp + BE64(ti) + BE64(st)):
        return False  # definitely absent; safe

    # Layer 2: exact lookup (in-memory HashSet, <10 μs)
    return (origin_fp, ti, st) in exact_collision_set

def handle_collision(ti: int, origin_fp: bytes, st: int):
    """Handle a collision: (TI, ST) has been used; automatically switch to the next TI."""
    # Record the collision in the audit log
    audit_log.record(COLLISION_DETECTED, origin_fp, ti, st)
    # SequenceToken continues to increase
    # Return the next available TI
    return allocate_next_ti_skip_collision()
```

Recommended Bloom Filter parameters:

Hot-window size: number of TIs in the most recent hour (about 60,000 TPS × 3,600 s ≈ 216 million entries).  
False-positive rate: 0.01% (`p=0.0001`).  
Required memory: about 600 MB (acceptable).  
Use an exact HashSet as the second confirmation layer.

### 7.3 Pending-state management

```python
def create_pending_anchor(
    anchor_type:      int,     # 3-7 correspond to P3-P7
    anchor_data:      bytes,   # serialized Anchor (including EEA)
    missing_fields:   list[dict],  # [{field_name, signer_fingerprint}]
    timeout_ti:       int,     # timeout TI (pending_since + TI count for 24 hours)
) -> bytes:                    # returns anchor_id
    """Create an Anchor in Pending state."""
    anchor_id = extract_anchor_id(anchor_data)
    pending_store.write(PendingAnchor(
        anchor_id       = anchor_id,
        anchor_type     = anchor_type,
        anchor_data     = anchor_data,
        missing_fields  = missing_fields,
        status          = PENDING,
        pending_since   = current_ti(),
        pending_timeout = timeout_ti,
    ))
    return anchor_id

def complete_pending_anchor(
    anchor_id:        bytes,
    field_name:       str,
    late_signature:   bytes,  # 64 B supplementary signature
    signer_claim_ref: bytes,  # 32 B ClaimAnchor of the party adding the signature
    sign_ti:          int,    # TI at the time of supplementary signing
) -> bool:
    """Add a missing field to a Pending Anchor and activate it when complete.

    Construct the late_signature signing input as follows:
        original_sign_payload = original signing input (same as at normal issuance)
        late_sign_payload = original_sign_payload + b"LateSign.v1" + BE64(sign_ti)
        late_signature = Sign(signer_sk, H(late_sign_payload))

    A verifier SHOULD reconstruct this input and verify the signature.
    """
    pending = pending_store.get(anchor_id)
    if pending is None or pending.status != PENDING:
        return False
    if current_ti() > pending.pending_timeout:
        pending.status = EXPIRED
        pending_store.update(pending)
        return False

    # Fill the missing field
    pending.fill_field(field_name, late_signature, signer_claim_ref, sign_ti)
    pending.remove_missing(field_name)

    # Activate the Anchor once every missing field has been filled
    if not pending.missing_fields:
        activate_anchor(pending)
        pending.status = ACTIVE
        pending_store.update(pending)

    return True

def purge_expired_pending():
    """Scheduled task: remove timed-out Pending Anchors."""
    expired = pending_store.query_expired(current_ti())
    for anchor in expired:
        anchor.status = EXPIRED
        audit_log.record(PENDING_EXPIRED, anchor.anchor_id)
    pending_store.bulk_update(expired)
```

### 7.4 Caching strategy

Three cache layers (see GNOMON-PERF-001 §3.4 for details):

L1 cache (process memory, <1 ms, about 32 GB):

- Stores EEA verification results from the most recent hour.
- Key: AnchorID.
- Value: `{valid, verified_at_ti, layer_results}`.
- TTL: `min(ValidUntil - current_ti, 3600 s)`.
- Invalidation: clear immediately when a RevocationRecord arrives.

L2 cache (Redis cluster, <5 ms, about 128 GB):

- Stores Anchors (EEA · ClaimAnchor) from the most recent 7 days.
- Revocation status: keep all entries resident, <200 MB.

L3 storage (PostgreSQL, <50 ms):

- Stores all history, partitioned by TI.
- Seven-day hot partition: NVMe SSD.
- Historical archive: HDD / object storage.

Cache consistency:

RevocationRecord arrives → immediately clear L1 / L2 cache.  
KeyPackage expires → do not clear the cache (historical EEAs remain valid).

## 8. Revocation mechanism

### 8.1 RevocationRecord

RevocationRecord is GnomonSystem's state-change mechanism. Nothing is deleted; only a revocation marker is added (append-only).

| Field | Length | Description |
|---|---:|---|
| `revocation_id` | 32 B | `H(all fields)` |
| `claim_anchor_id` | 32 B | ClaimAnchor being revoked (all zeros = bulk revocation by `entity_fp`) |
| `entity_fingerprint` | 32 B | EntityFingerprint of the subject being revoked |
| `attribute_type` | 2 B | `0` = revoke all types |
| `revocation_time` | 8 B | TI at which revocation takes effect |
| `revocation_reason` | 1 B | `0x01` = security risk; `0x02` = voluntary cancellation; `0x03` = legal mandate; `0x04` = cascade revocation |
| `issuer_fingerprint` | 32 B | Fingerprint of the institution initiating revocation |
| `revocation_sig` | 64 B | SM2 signature by the initiating institution |
| `override_grace` | 1 B | `0` = honor grace period; `1` = immediate effect |
| `regulation_reference` | 32 B | `H(regulatory document)`; required for mandatory revocation |
| **Total** | **about 200 B** |  |

Time-cut semantics:

`RevocationRecord.revocation_time = T_revoke` (a TI value).

Events that have already occurred (`EEA.TI ≤ T_revoke`):

Validate using EEA.TI as the basis. If the ClaimAnchor was valid at EEA.TI, the subject proof for that event remains valid.
No retroactive effect: revocation does not invalidate already completed historical collaboration.

Future events (`EEA.TI > T_revoke`):

If verification finds that the ClaimAnchor has been revoked, return `E032` and reject it.

### 8.2 Broadcast and propagation

```python
# Broadcast deadline: TI count corresponding to 30 minutes (assuming 1 TI = 1 μs)
# 30 min = 30 × 60 × 1,000,000 μs = 1,800,000,000 TI
BROADCAST_DEADLINE_TI = 1_800_000_000  # about 1.8 × 10^9 TI

def broadcast_revocation(rr: RevocationRecord) -> BroadcastResult:
    """Broadcast a RevocationRecord using both Push and Pull modes.
    SLA: reach 99% of L2 nodes within 30 minutes.
    See Engineering Challenge Specification §2.3 for details.
    """
    result = BroadcastResult()
    all_nodes = get_registered_l2_nodes()

    # Push mode: broadcast concurrently to all known nodes
    futures = []
    for node in all_nodes:
        future = async_push(node.endpoint, rr)
        futures.append((node, future))

    # Wait for responses (10-second timeout)
    for node, future in futures:
        try:
            resp = future.result(timeout=10)
            if resp.accepted:
                result.covered_nodes.add(node.fingerprint)
                if resp.duplicate:
                    result.already_known.add(node.fingerprint)
        except TimeoutError:
            result.failed_nodes.add(node.fingerprint)

    # Record broadcast status
    revocation_store.update_broadcast_status(
        rr.revocation_id,
        coverage_count = len(result.covered_nodes),
        broadcast_deadline = current_ti() + BROADCAST_DEADLINE_TI,
    )

    # Supplement with Pull mode (does not depend on Push success)
    # Other nodes actively pull the latest RevocationRecords every 3 minutes.
    # See SyncService.PullRevocationsSince.

    # Check the SLA
    coverage_rate = len(result.covered_nodes) / len(all_nodes)
    if coverage_rate < 0.99:
        schedule_retry(rr, failed_nodes=result.failed_nodes)

    return result

def verify_revocation_status(
    anchor_id: bytes,
    at_ti:     int,
) -> RevocationStatus:
    """Fast revocation-status lookup.
    Uses revocation_index (an in-memory table); response time <1 ms.
    """
    # Layer 1: Bloom Filter (0.01 ms)
    if not revocation_bloom.possibly_contains(anchor_id):
        return NOT_REVOKED

    # Layer 2: exact lookup (in-memory HashTable, 0.1 ms)
    rr = revocation_index.get(anchor_id)
    if rr is None:
        return NOT_REVOKED

    # Time cut: revocation time versus query time
    if rr.revocation_time <= at_ti:
        return REVOKED_AT_TI(rr.revocation_time)
    else:
        return NOT_YET_REVOKED  # revocation occurs after at_ti; it was still valid then
```

### 8.3 Handling degraded EEAs

```python
def handle_degraded_eea(eea: EEA, verifier_policy: VerifierPolicy) -> VerifyResult:
    """Handle an EEA with degraded_mode=1."""
    if not eea.degraded_mode:
        return None  # normal EEA; nothing to handle here

    result = VerifyResult()
    result.add_warning(W005, "EEA was produced during a degraded period; TI precision may be lower")

    # Look up the degraded-mode record (DegradedModeRecord)
    degraded_record = query_degraded_record(eea.origin_fingerprint, eea.temporal_index)
    if degraded_record:
        result.degraded_period = (
            degraded_record.degraded_start_ti,
            degraded_record.degraded_end_ti,
        )
        result.mapping_available = (degraded_record.mapped_at is not None)

    # Decide whether to accept according to verifier policy
    if verifier_policy == STRICT:
        # High-security judicial / financial scenario: reject a degraded EEA
        result.valid = False
        result.error = E_DEGRADED_NOT_ACCEPTED
    elif verifier_policy == STANDARD:
        # Standard scenario: accept but mark it
        result.valid = True
    else:
        # Permissive scenario (e.g. logging): accept
        result.valid = True

    return result
```

## 9. Verification specification

### 9.0 Self-contained verification boundary for an EEA

This section clarifies what can be verified independently when an EEA is detached from the issuing node, what additional information is needed for verification, and one key distinction: what is transferred is proof, not business content. This precisely defines the boundary of Gnomon's “permissionless verification” property.

#### 9.0.1 Self-contained checks (EEA + L1 public key only)

Once issued by an L2 node, the following checks can be completed **independently of the issuing node**. The verifier only needs the L2 node's public key (endorsed through the L1 KeyPackage / NodeCertificate):

- **Signature validity:** verify DigitalSignature with the L2 public key.
- **AnchorID integrity:** recompute `H(domain_tag ∥ TI ∥ OriginFP ∥ ST ∥ Salt)` and compare.
- **Temporal authenticity:** verify that TI lies in the TI allocation range (`ti_range`) of the ChildTHK carried by that L2 node.
- **Single-point existence:** prove that “this event was signed by this node at this TI and has not been tampered with.”

Key properties:

- No need to contact the issuing node again.
- No need for network-wide consensus.
- Any verifier holding the L1 public key can verify independently.

This fundamentally differs from systems that depend on a global ledger (such as blockchains): Gnomon verification relies on the cryptographic chain itself, not on a ledger.

#### 9.0.2 Checks requiring additional information

The following checks **cannot be completed using one EEA alone**; the verifier must actively obtain additional information:

**Revocation-status check:**

An EEA does not carry revocation information.
The verifier must query the RevocationRecord (see §8) to determine whether the referenced Anchor has been revoked.
Note: revocation is not retroactive; EEA.TI is the time-cut basis (see §9.x, Time Cut).

**ChainProof-chain verification:**

Verifying the integrity of a causal chain requires the preceding EEA.
A single EEA proves only “I reference the hash of a predecessor.”
To verify that the predecessor really exists, obtain the preceding EEA (or use VP / checkpoints; see §4).

**SemanticAnchor semantic verification:**

L2 nodes do not store P3–P7 reference parameters (semantic isolation).
The verifier must obtain `SemanticAnchorInput` (the seven reference values) from a party to reconstruct SA and verify it.
If SA is nonzero but input parameters are not supplied, return `E035` (see §5.3).

**Cross-layer full integrity (full verification):**

Query all upper-layer Anchors corresponding to nonzero `Pn_ref` values in parallel (see §9.1, `verify_depth=3`).

#### 9.0.3 What is transferred is proof, not business content

An EEA and Anchors at every layer **do not contain business plaintext**; they contain only SM3 digests:

`ContentHash` · `AttributeHash` · `ScopeHash` · `RelationHash` · `YieldHash` ...

All are hash commitments and cannot be reversed to recover the original text.

Meaning:

- EEAs can be transferred publicly and verified network-wide because they disclose no business content.
- From an EEA, a verifier can confirm “something happened; who signed it; it was not tampered with; and when.”
- To learn “what the specific content was,” the verifier must obtain the plaintext from a party and calculate its SM3 hash independently to compare with the commitment in the Anchor.

This is exactly the purpose of semantic isolation:
Proof (hashes) can be transferred publicly; private content (plaintext) stays with the parties.
As a “notary office,” the L2 node witnesses only the digest and does not hold the content.

#### 9.0.4 Boundary summary

- Can be verified independently (proof properties): signature · AnchorID · timing · single-point existence.
- Additional information required: revocation status (RevocationRecord) · chain (preceding EEA / VP) · semantics (reference parameters).
- Transferred object: proof (hash commitment), not business plaintext.
- Trust root: one L1 public key verifies all EEAs issued by its L2 nodes.

### 9.1 Verification depth

`verify_depth = 1` (minimal):

- Verify: `EEA.DigitalSignature` + AnchorID.
- Do not verify: ChainProof continuity · SemanticAnchor references.
- Applicable to: high-frequency real-time scenarios (each operation).
- Latency: <1 ms.

`verify_depth = 2` (standard):

- Verify: all above + ChainProof + VerificationProof (if present) + validity of P3_ref.
- Applicable to: routine business verification.
- Latency: <10 ms (including ClaimAnchor lookup).

`verify_depth = 3` (full):

- Verify: all above + every nonzero `Pn_ref` + layer-level constraints + `event_data_hash` + THK-chain time validation.
- Full-chain time-validation path:
  1. Verify `EEA.DigitalSignature` (P2 signature).
  2. Verify that KeyPackage was correctly signed by the L1 and that `EEA.TI ∈ [ti_range_start, ti_range_end)` of the ChildTHK carried by the KeyPackage.
  3. Verify that the ChildTHK was correctly signed by the RootTHK (including the OpCertificate chain), and that the KeyPackage TI range is within the ChildTHK TI range.
  4. Verify that the RootTHK `time_commitment` matches its physical-time claim.
  5. If `max_issuance_delay` is enabled, verify `(EEA issuance time - ChildTHK issuance time) ≤ max_issuance_delay`.
- Applicable to: regulatory audits, judicial evidence, and compliance checks.
- Latency: <100 ms (parallel queries for all references + THK chain).
- Parallel requirement: all `Pn_ref` queries MUST execute in parallel; do not wait for them serially.

### 9.2 Full EEA verification algorithm (pseudocode)

```python
def verify_eea_full(
    eea:           EEA,
    verify_depth:  int = 3,
    at_ti:         int | None = None,  # None = use eea.temporal_index
    sa_input:      SemanticAnchorInput | None = None,  # required if SA is nonzero
) -> VerifyResult:
    """Full EEA verification algorithm.
    at_ti: verification time (for time-cut checks); defaults to the EEA's own TI.
    sa_input: SemanticAnchor inputs; MUST be provided if eea.semantic_anchor is nonzero.
    """
    result = VerifyResult()
    check_ti = at_ti if at_ti is not None else eea.temporal_index

    # ── Basic verification (performed at every depth) ────────

    # B1: AnchorID integrity
    expected_anchor_id = H(
        b"Polaris.Anchor.v1"
        + BE64(eea.temporal_index)
        + eea.origin_fingerprint
        + BE64(eea.sequence_token)
        + eea.salt
    )
    if eea.anchor_id != expected_anchor_id:
        return VerifyResult(valid=False, error=E001)

    # B2: L2 node authentication
    node_cert = get_node_certificate(eea.origin_fingerprint)
    if node_cert is None:
        return VerifyResult(valid=False, error=E002)
    if not is_valid_cert(node_cert, check_ti):
        return VerifyResult(valid=False, error=E002)

    # B3: KeyPackage version
    if eea.key_version != get_current_key_version(eea.origin_fingerprint):
        # Allow a historical version (time-cut); verify only that the key was valid then.
        if not was_valid_key_version(eea.key_version, eea.temporal_index):
            return VerifyResult(valid=False, error=E003)

    # B4: DigitalSignature
    pk_l2 = node_cert.public_key
    signing_payload = (
        b"Polaris.Anchor.v1"
        + eea.anchor_id
        + BE64(eea.temporal_index)
        + eea.origin_fingerprint
        + BE64(eea.sequence_token)
        + eea.chain_proof
        + BE32(eea.key_version)
        + bytes([eea.degraded_mode])
        + bytes(3)  # reserved_future: 3 B, MUST=0
    )
    if not Verify(pk_l2, SM3(signing_payload), eea.digital_signature):
        return VerifyResult(valid=False, error=E004)

    # B5: TI is within the ChildTHK allocation range
    child_thk = get_child_thk_from_keypackage(kp)
    if child_thk and not (child_thk.ti_range_start <= eea.temporal_index < child_thk.ti_range_end):
        result.add_warning(W007, "TI is outside the ChildTHK allocation range (ti_range)")

    # B6: Degraded-mode check
    if eea.degraded_mode:
        degraded_result = handle_degraded_eea(eea, verifier_policy)
        result.merge(degraded_result)
        if not degraded_result.valid:
            return result

    if verify_depth < 2:
        result.valid = True
        return result

    # ── Standard verification (depth >= 2) ───────────────────

    # S1: ChainProof verification
    prev_eea = get_prev_eea(eea.origin_fingerprint, eea.sequence_token - 1)
    if prev_eea is None:
        expected_cp = H(bytes(104))  # root EEA
    else:
        expected_cp = H(
            prev_eea.anchor_id
            + BE64(prev_eea.temporal_index)
            + prev_eea.digital_signature
        )
    if eea.chain_proof != expected_cp:
        return VerifyResult(valid=False, error=E005)

    # S2: SequenceToken monotonicity
    if prev_eea and eea.sequence_token <= prev_eea.sequence_token:
        return VerifyResult(valid=False, error=E006)

    # S3: VerificationProof (if present)
    if eea.verification_proof and prev_eea and prev_eea.verification_proof:
        expected_vp = H(prev_eea.anchor_id + prev_eea.verification_proof)
        if eea.verification_proof != expected_vp:
            result.add_warning(W008, "VerificationProof does not match the predecessor")

    if verify_depth < 3:
        result.valid = True
        return result

    # ── Full verification (depth == 3) ────────────────────────

    # F1: SemanticAnchor verification (if present)
    if eea.semantic_anchor and eea.semantic_anchor != ZERO_32:
        if sa_input is None:
            return VerifyResult(valid=False, error=E035,
                msg="SemanticAnchor is nonzero but input parameters were not provided")
        sa_result = verify_semantic_anchor(eea, sa_input, verify_depth=3)
        result.merge(sa_result)

    # (V4.1 cluster nonce revision statement is retained in the change summary;
    #  it is not repeated here.)

    # F2: THK-chain time validation (added in V3.8)
    # Verify the trust chain: RootTHK → ChildTHK → KeyPackage → EEA
    thk_result = verify_thk_chain(
        eea               = eea,
        depth             = verify_depth,
        at_ti             = check_ti,
        current_wallclock = get_current_wallclock(),  # current physical time (nanoseconds)
    )
    result.merge(thk_result)

    # Internal logic of verify_thk_chain (pseudocode):
    #   def verify_thk_chain(eea, depth, at_ti, wallclock):
    #       # 1. Parse trust chain
    #       kp = get_key_package(eea.origin_fingerprint, eea.key_version)
    #       if kp is None: return (False, "KeyPackage does not exist")
    #       child_thk = get_child_thk_by_commitment(kp.child_thk_commitment)
    #       if child_thk is None: return (False, "ChildTHK does not exist")
    #       root_thk = get_root_thk_by_commitment(child_thk.parent_root_thk_id)
    #       if root_thk is None: return (False, "RootTHK does not exist")
    #
    #       # 2. Verify RootTHK signature (L1 root key)
    #       if not verify_root_thk(root_thk): return (False, "RootTHK signature invalid")
    #
    #       # 3. Verify RootTHK-chain integrity
    #       prev_root = get_prev_root_thk(root_thk)
    #       if prev_root and root_thk.prev_root_commitment != prev_root.time_commitment:
    #           return (False, "RootTHK chain is broken")
    #
    #       # 4. Verify ChildTHK (OpCertificate chain: root key → OpCert → operational key → ChildTHK)
    #       op_cert = get_op_certificate(child_thk)
    #       if not op_cert or not verify_op_cert(op_cert):
    #           return (False, "OpCertificate is invalid")
    #       if not verify_child_thk(child_thk, op_cert.op_pubkey):
    #           return (False, "ChildTHK signature invalid")
    #
    #       # 5. Verify ChildTHK.TI range ⊆ RootTHK.TI range
    #       if not (root_thk.ti_range_start <= child_thk.ti_range_start and
    #               child_thk.ti_range_end <= root_thk.ti_range_end):
    #           return (False, "ChildTHK TI range is outside the RootTHK range")
    #
    #       # 6. Verify KeyPackage ↔ ChildTHK binding
    #       if kp.child_thk_commitment != child_thk.child_commitment:
    #           return (False, "KeyPackage and ChildTHK binding does not match")
    #
    #       # 7. Verify EEA.TI ∈ ChildTHK.TI range
    #       if not (child_thk.ti_range_start <= eea.temporal_index < child_thk.ti_range_end):
    #           return (False, "EEA.TI is outside the ChildTHK TI range")
    #
    #       # 8. Validity-period check (if max_issuance_delay is enabled)
    #       if child_thk.max_issuance_delay > 0:
    #           delta_seconds = (wallclock - child_thk.t_utc) / 1_000_000_000  # nanoseconds → seconds
    #           if delta_seconds > child_thk.max_issuance_delay:
    #               return (False, f"TI use-validity period exceeded: {delta_seconds}s > {child_thk.max_issuance_delay}s")
    #
    #       return (True, "THK-chain verification passed")

    result.valid = not result.has_critical_errors()
    return result
```

### 9.3 Full SemanticAnchor verification algorithm (pseudocode)

See §5.3.

## 10. Protocol messages (Protobuf)

```protobuf
// gnomon/v1/polaris.proto
syntax = "proto3";
package gnomon.v1;

// ── Core data structures ──────────────────────────────────
message EEA {
  uint32 version             = 1;
  bytes  anchor_id           = 2;   // 32 B
  uint64 temporal_index      = 3;
  bytes  origin_fingerprint  = 4;   // 32 B
  uint64 sequence_token      = 5;
  bytes  chain_proof         = 6;   // 32 B
  bytes  digital_signature   = 7;   // 64 B
  bytes  salt                = 13;  // 16 B CSPRNG; used in AnchorID calculation; MUST be persisted with the EEA
  bytes  verification_proof  = 8;   // 32 B, optional
  bytes  semantic_anchor     = 9;   // 32 B, optional; all zeros = anonymous
  repeated EEAExtension extensions = 10;
  uint32 key_version         = 11;
  bool   degraded_mode       = 12;
}

message EEAExtension {
  uint32 extension_type = 1;
  uint32 version        = 2;
  uint32 hdr_flags      = 3;   // uint8 bitmap; proto3 uses uint32; bit0=critical
  bytes  payload        = 4;
}

message SemanticAnchorInput {
  uint32 version          = 1;  // SA calculation version; current = 1
  bytes  eea_anchor_id    = 2;  // 32 B, MUST
  bytes  p3_ref           = 3;  // 32 B ClaimAnchorID; all zeros = none
  bytes  p4_ref           = 4;  // 32 B ScrollAnchorID; all zeros = none
  bytes  p5_ref           = 5;  // 32 B GrantAnchorID; all zeros = none
  bytes  p6_ref           = 6;  // 32 B BondAnchorID; all zeros = none
  bytes  p7_ref           = 7;  // 32 B YieldAnchorID; all zeros = none
  bytes  event_data_hash  = 8;  // 32 B H(business data)
  bytes  raw_event_data   = 9;  // optional; used to verify event_data_hash
}

// ── Polaris service ───────────────────────────────────────
service PolarisService {
  // Submit an EEA (business system → L2 node)
  rpc SubmitEEA(SubmitEEARequest) returns (SubmitEEAResponse);

  // Submit a batch (bidirectional stream)
  rpc SubmitEEABatch(stream SubmitEEARequest) returns (stream SubmitEEAResponse);

  // Query one EEA
  rpc GetEEA(GetEEARequest) returns (GetEEAResponse);

  // Query by TI range (streaming response)
  rpc QueryEEAByRange(QueryEEARequest) returns (stream EEA);

  // Verify an EEA (with depth control)
  rpc VerifyEEA(VerifyEEARequest) returns (VerifyEEAResponse);

  // Verify causality (O(1) VP path)
  rpc VerifyCausality(VerifyCausalityRequest) returns (VerifyCausalityResponse);

  // Subscribe to a real-time EEA stream (regulatory / audit nodes)
  rpc SubscribeEEAStream(EEAStreamRequest) returns (stream EEA);

  // Add a supplementary signature to a Pending Anchor
  rpc CompletePendingAnchor(CompletePendingRequest) returns (GnomonResponse);
}

message SubmitEEARequest {
  uint32              version        = 1;
  EEA                 eea            = 2;
  SemanticAnchorInput semantic_input = 3;  // optional; used for SA verification
}

message SubmitEEAResponse {
  GnomonResponse response      = 1;
  bytes          anchor_id     = 2;   // 32 B; confirms it was written
  uint64         stored_at_ti  = 3;
}

message VerifyEEARequest {
  uint32              version        = 1;
  bytes               anchor_id      = 2;   // 32 B
  uint32              verify_depth   = 3;   // 1=minimal, 2=standard, 3=full
  SemanticAnchorInput semantic_input = 4;   // optional (required if SA is nonzero)
  uint64              at_ti          = 5;   // verification time; 0 = use the EEA's own TI
}

message VerifyEEAResponse {
  GnomonResponse       response      = 1;
  bool                 valid         = 2;
  uint32               verify_depth  = 3;
  repeated LayerResult layer_results = 4;
  repeated uint32      warnings      = 5;
  bool                 degraded_mode = 6;
}

message LayerResult {
  uint32 layer      = 1;  // 2=P2, 3=P3, 4=P4, 5=P5, 6=P6, 7=P7
  bool   valid      = 2;
  uint32 error_code = 3;
  bytes  anchor_id  = 4;  // 32 B
}

message VerifyCausalityRequest {
  uint32         version                  = 1;
  bytes          earlier_anchor_id        = 2;  // 32 B; EEA claimed to be earlier
  bytes          later_anchor_id          = 3;  // 32 B; EEA claimed to be later
  repeated bytes intermediate_anchor_ids = 4;  // intermediate AnchorIDs (may be sparse)
  repeated bytes checkpoint_vps          = 5;  // VP for corresponding checkpoints (optional)
}

message VerifyCausalityResponse {
  GnomonResponse response         = 1;
  bool           causally_before = 2;  // whether earlier truly precedes later
  string         method           = 3;  // "VP" = O(1); "ChainProof" = O(n)
}

message EEAStreamRequest {
  uint32 version          = 1;
  bytes  subscriber_fp    = 2;  // 32 B; subscriber fingerprint
  bytes  subscriber_cert  = 3;  // 64 B; authorization-certificate signature
  uint64 from_ti          = 4;  // start pushing from this TI
  uint32 extension_type   = 5;  // 0 = all; >0 = filter for a specific subprotocol
}

message CompletePendingRequest {
  uint32 version            = 1;
  bytes  anchor_id          = 2;  // 32 B Pending Anchor
  string missing_field_name = 3;
  bytes  late_signature     = 4;  // 64 B
  bytes  signer_claim_ref   = 5;  // 32 B ClaimAnchor of the party adding the signature
  uint64 sign_ti            = 6;
}
```

## 11. Security considerations

### 11.1 ChainProof security boundaries

Attacks ChainProof defends against:

- ✅ Historical insertion: insert at position `k` → every subsequent ChainProof becomes invalid.
- ✅ Historical deletion: delete position `k` → ChainProof at position `k+1` becomes invalid.
- ✅ Historical replacement: modify any field → AnchorID changes → subsequent ChainProof values become invalid.

Scenarios ChainProof does not defend against:

- ✗ An L2 node truncates the end of the chain (retains only the first N EEAs).
  - Mitigation: regulatory nodes subscribe in real time and keep independent backups.
- ✗ A completely new forged chain is rebuilt from genesis.
  - Mitigation: `NodeCertificate.valid_from` limits the signing time; the time-cut principle associates historical signatures with historical public keys.

### 11.2 SemanticAnchor security

Defended against (V1.0):

- ✅ Cross-EEA transplant (T10): AnchorID is embedded in the 224-byte input.
- ✅ Downgrade attack (T11): check the `extension_type`.
- ✅ Time-backdating attack (T12): use EEA.TI as the verification-time basis.

Points to note:

SA is an SM3 hash, and an L2 node does not verify the validity of SA references (the node does not know the parameters such as `P3_ref`).
The verifier is responsible for SemanticAnchor semantic verification and holds the `SemanticAnchorInput` parameters.
The verifier MUST obtain SA input parameters from the business system or a trusted source.

### 11.3 Semantic isolation

Data stored by an L2 node:

```text
AnchorID (32 B)
TemporalIndex (8 B)
OriginFingerprint (32 B)
SequenceToken (8 B)
ChainProof (32 B)
DigitalSignature (64 B)
SemanticAnchor (32 B, if present)
```

Data not stored by an L2 node:

- Business-data plaintext (`event_data_hash` stores only a hash).
- SemanticAnchorInput parameters (`P3_ref`, etc. are held by the business system).
- Any content that could reconstruct business semantics.

Guarantee: even if an L2 node is completely controlled by an attacker, the attacker cannot learn any business content from the node's storage.

## 12. Test vectors

### 12.1 EEA core-field test vector

```python
# All inputs use fixed values; implementations MUST produce the same output.
import hashlib

def sm3(data: bytes) -> bytes:
    # In production, use the national SM3 implementation; SHA3-256 is used here for demonstration only.
    return hashlib.sha3_256(data).digest()

# Fixed inputs
TI              = 1000000001
ORIGIN_FP       = bytes.fromhex("ab" * 32)   # SM3(L2 public key), fixed test value
ST              = 1
PREV_ANCHOR_ID  = bytes.fromhex("00" * 32)   # root EEA; predecessor is all zeros
PREV_TI         = 0
PREV_SIG        = bytes.fromhex("00" * 64)
KEY_VERSION     = 1
DEGRADED_MODE   = 0
SALT            = bytes.fromhex("cd" * 16)

# Step 1: ChainProof
chain_proof = sm3(PREV_ANCHOR_ID + PREV_TI.to_bytes(8,'big') + PREV_SIG)
print(f"ChainProof: {chain_proof.hex()}")
# Expected value: the actual output of sha3_256(0 × 104)

# Step 2: AnchorID (independent of the signature)
anchor_id = sm3(
    b"Polaris.Anchor.v1"
    + TI.to_bytes(8,'big')
    + ORIGIN_FP
    + ST.to_bytes(8,'big')
    + SALT
)

# Step 3: signing_payload (137 B)
signing_payload = (
    b"Polaris.Anchor.v1"              # 17 B
    + anchor_id                       # 32 B
    + TI.to_bytes(8,'big')            # 8 B
    + ORIGIN_FP                       # 32 B
    + ST.to_bytes(8,'big')            # 8 B
    + chain_proof                     # 32 B
    + KEY_VERSION.to_bytes(4,'big')   # 4 B
    + bytes([DEGRADED_MODE])          # 1 B
    + bytes(3)                        # reserved_future: 3 B, MUST=0
)
raw_len = 17+32+8+32+8+32+4+1+3
assert raw_len == 137, f"Incorrect signing-input length: {raw_len}"
print(f"signing_payload_hash: {signing_payload.hex()}")

# Step 4: DigitalSignature
# digital_sig = SM2_Sign(sk_l2, SM3(signing_payload))  # prehash: pass e = SM3(original input)
```

### 12.2 SemanticAnchor test vector

```python
# P3+P4+P5 combination test vector
ANCHOR_ID    = bytes.fromhex("11" * 32)  # EEA.AnchorID
P3_REF       = bytes.fromhex("22" * 32)  # ClaimAnchor.AnchorID
P4_REF       = bytes.fromhex("33" * 32)  # ScrollAnchor.AnchorID
P5_REF       = bytes.fromhex("44" * 32)  # GrantAnchor.AnchorID
ZERO_32      = bytes(32)
EVENT_HASH   = sm3(b"test_contract_canonical_bytes")

sa_input_224 = (
    ANCHOR_ID    # 32 B; binds to EEA
    + P3_REF     # 32 B
    + P4_REF     # 32 B
    + P5_REF     # 32 B
    + ZERO_32    # 32 B; no P6 reference
    + ZERO_32    # 32 B; no P7 reference
    + EVENT_HASH # 32 B
)
assert len(sa_input_224) == 224

sa = sm3(sa_input_224)
print(f"SemanticAnchor [P3+P4+P5]: {sa.hex()}")

# All zeros (anonymous event)
sa_anon = bytes(32)
print(f"SemanticAnchor [anonymous]: {sa_anon.hex()}")
```

### 12.3 ChainProof continuity test vector

```python
# Chain validation for three EEAs
EEA_0_anchor_id = bytes.fromhex("aa" * 32)
EEA_0_ti        = 1000000001
EEA_0_sig       = bytes.fromhex("bb" * 64)

# ChainProof of EEA_1
cp_1 = sm3(EEA_0_anchor_id + EEA_0_ti.to_bytes(8,'big') + EEA_0_sig)
EEA_1_anchor_id = bytes.fromhex("cc" * 32)
EEA_1_ti        = 1000000002
EEA_1_sig       = bytes.fromhex("dd" * 64)

# ChainProof of EEA_2
cp_2 = sm3(EEA_1_anchor_id + EEA_1_ti.to_bytes(8,'big') + EEA_1_sig)

print(f"EEA_1 ChainProof: {cp_1.hex()}")
print(f"EEA_2 ChainProof: {cp_2.hex()}")
```

## 13. Error and warning codes

P2 Polaris Protocol error codes:

| Code | Name | Meaning |
|---|---|---|
| `E001` | `ANCHOR_ID_MISMATCH` | Recomputed AnchorID does not match (a field was tampered with) |
| `E002` | `NODE_CERT_INVALID` | L2 node certificate is invalid or revoked |
| `E003` | `KEY_VERSION_INVALID` | `key_version` does not match the historical record |
| `E004` | `DIGITAL_SIG_INVALID` | DigitalSignature verification failed |
| `E005` | `CHAIN_PROOF_BROKEN` | ChainProof is discontinuous (insertion / deletion / replacement) |
| `E006` | `SEQUENCE_TOKEN_INVALID` | SequenceToken is not monotonically increasing |
| `E007` | `VP_MISMATCH` | VerificationProof is inconsistent |
| `E008` | `TI_OUT_OF_RANGE` | TI is outside the ChildTHK TI allocation range (`ti_range_start`–`ti_range_end`) |
| `E009` | `TI_NOT_MONOTONIC` | TI is not monotonically increasing (within the same universe; rollback is allowed after a cross-universe switch) |

SA-related error codes:

| Code | Name | Meaning |
|---|---|---|
| `E030` | `SA_MISMATCH` | Reconstructed SemanticAnchor does not match |
| `E031` | `SA_REF_NOT_FOUND` | Referenced Anchor does not exist |
| `E032` | `SA_REF_EXPIRED` | Referenced Anchor was invalid when the event occurred |
| `E033` | `SA_EVENT_HASH_MISMATCH` | `event_data_hash` does not match the business data |
| `E034` | `SA_ANCHOR_TYPE_WRONG` | `extension_type` of `Pn_ref` does not match the layer |
| `E035` | `SA_INPUT_MISSING` | SemanticAnchor is nonzero but input parameters were not provided |

Warning codes:

| Code | Name | Meaning |
|---|---|---|
| `W005` | `DEGRADED_EEA` | EEA was produced during a degraded period; TI precision may be lower |
| `W007` | `TI_OUT_OF_KEYPKG_RANGE` | TI is outside the ChildTHK allocation range (V4.0: validate TI against `ChildTHK.ti_range`, not KeyPackage) |
| `W008` | `VP_INCONSISTENT` | VP is not continuous with the preceding node (may be ignored for a cross-node chain) |
| `W010` | `SA_SHOULD_CONSTRAINT` | A SemanticAnchor layer-level SHOULD constraint was not met |
| `W011` | `YIELD_DISPUTED` | The referenced YieldAnchor has a dispute record |
| `W012` | `ZKP_DEGRADED` | ZKP is unsupported; downgraded to commitment verification |
| `W013` | `PENDING_REF` | SemanticAnchor references an Anchor in Pending state |
| `W014` | `REVOCATION_BROADCAST_DELAY` | Revocation broadcast timed out (not completed within 30 minutes) |

(The V4.1 cluster nonce revision statement is retained in the change summary; it is not repeated here.)

## 14. Version history

| Version | Date | Description |
|---|---|---|
| V4.2 | 2026-08-02 | Protocol completion: fixed `VP_0` + `ChainProof_root` as protocol constants (non-negotiable hexadecimal values). Cross-reference the Merkle convergence rule in SEC-003 §5. Retained the V4.1 cluster nonce. |
| V3.8 | 2026-06-18 | P1-2 improvement: `verify_depth=full (3)` adds full-chain THK time validation (five-step validation path: EEA signature → KeyPackage → ChildTHK → RootTHK → `max_issuance_delay` validity check); §9.2 adds F2 THK-chain time-validation pseudocode; updated the §9.1 full-depth description. |
| V1.2.3 | 2026-06-13 | Corrected the AnchorID-reconstruction formula in the §3.2 `verify_chain` pseudocode to match the authoritative §2.1.1 formula (includes `domain_tag` / Salt, excludes ChainProof / signature). The protocol definition in §2.1 was always correct; only the pseudocode was wrong. Source: review D06. |
| V1.2.2 | 2026-06-06 | Added §9.0, the EEA self-contained verification boundary (self-contained checks, checks requiring additional information, and the principle that proof—not content—is transferred). Originated from engineering-verification discussions. |
| V1.2.1 | 2026-06-06 | Added §3.4, timing and causality across L2 nodes (TI uniqueness guaranteed by range allocation, partial order for concurrent events without causality, cross-node ChainProof references, and no L2 mutual recognition needed within one L1 domain). Originated from implementer feedback during engineering verification. |
| V1.2 | 2026-06-04 | Fixed the circular dependency between AnchorID and DigitalSignature: expanded the EventAnchor core to 192 B and added Salt (16 B); changed AnchorID to `H(domain_tag ∥ TI ∥ OriginFingerprint ∥ SequenceToken ∥ Salt)`; an EEA with VerificationProof is 224 B; updated field order, test vectors, and upper-layer Anchor sizes. |
| V1.1 | 2026-06-03 | Clarified the signature cycle in field-construction order; added the checkpoint mechanism for O(1) causal verification; specified SequenceToken persistence; added the exact Late Signature format (`b"LateSign.v1"`); defined the value of `BROADCAST_DEADLINE_TI` and referenced the Engineering Challenge; clarified that SA verification requires external input parameters (added E035); other small optimizations. |
| V1.0 | 2026-06 | Official release · design frozen. Complete definitions: legacy EEA structure, ChainProof, VerificationProof, SemanticAnchor, ExtensionHeader, L2 issuance flow, collision detection, Pending state, revocation mechanism, verification-algorithm pseudocode, Protobuf messages, test vectors, and error codes. |

## Release review item (non-normative)

The V4.4 source specification has one pre-release interoperability clarification item:

The specification says `ExtensionHeader.version` is at absolute EEA byte offset 194, while also placing ExtensionHeader after the optional 32-byte VP. Without VP, the header starts at offset 192 after the core and its version byte is at 194; with VP, the header starts at offset 224 and its version byte is at 226. Confirm whether the offset is absolute or relative to the end of the optional fields, and specify how a parser locates the header under a fixed-offset rule.

---

*RFC-P2-001 ·* GnomonSystem *(Polaris) Protocol · GnomonSystem Protocol Baseline v4.4 · English Version· 2026-10-20*
