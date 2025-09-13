# Simple Certificate Specification (Complete)

## Common rules
- **Container:** Standard Base64 (no line breaks).
- **Endianness:** All multi-byte integers are **big-endian**.
- **Strings:** UTF-8, no NUL terminator.
- **Counts:** Single byte counts.
- **TBS (to-be-signed) region:** From **Magic** through **Flags** (inclusive).

---

# Binary layout

## Shared header
| # | Field | Size | Notes |
|---|---|---:|---|
| 1 | **Magic** | 3 | Fixed `08 44 53` (`"CERT"` when Base64). |
| 2 | **AlgVer** | 1 | `0x01 = Ed25519 v1`. Others reserved. |

The following structure applies to `AlgVer = 0x01` (Ed25519 v1 — fixed sizes, no length fields).

| # | Field | Size | Notes |
|---|---|---:|---|
| 3 | **KeyId** | 16 | Must be `SHA-256(PubKey)[0..15]`. |
| 4 | **PubKey** | 32 | Raw Ed25519 public key. |
| 5 | **DescLen** | 1 | 0–255. Description is **required** (policy may enforce ≥1). |
| 6 | **Desc** | DescLen | UTF-8. |
| 7 | **UserDescCount** | 1 | N descriptors (0–255). |
| 8 | **For i in 1..N: Type** | 1 | See enum below. |
| 9 | **For i: ValLen** | 2 | UTF-8 value length (UINT16BE). |
| 10 | **For i: Value** | ValLen | UTF-8. |
| 11 | **Flags** | 2 | Permission bitmask (see table). **TBS ends here.** |
| 12 | **SigCount** | 1 | **Must be ≥ 1**. |
| 13 | **For j in 1..M: SignKeyId** | 16 | Signer’s KeyId (same 16-byte rule). **No length field.** |
| 14 | **For j: Signature** | 64 | Raw Ed25519 signature. **No length field.** |

## Descriptor Type (1 byte)
- `0x01` — Username
- `0x02` — Email
- `0x03` — Domain
> Descriptors are **optional**. Multiple entries (even of same type) allowed.

## Flags (2 bytes, bitmask)
- `0x0001` — **Root CA**
- `0x0002` — **Intermediate CA**
- `0x0004` — **CA**
- `0x0100` — **Document Signer**
- `0x0200` — **Template Signer**
- Other bits **reserved** (must be `0` on encode; ignore on decode).

---

## Flag semantics and policy

### Role implications
- **Root CA (`0x0001`)**  
  - **Must be self-signed** (at least one signature entry where `SignKeyId == KeyId` and the signature verifies).  
  - Should also carry `CA (0x0004)` to indicate certificate-signing capability (recommended).

- **Intermediate CA (`0x0002`)**  
  - **May sign** only **CA (`0x0004`)** or **Intermediate CA (`0x0002`)** certificates.  
  - Usually also sets `CA (0x0004)`.

- **CA (`0x0004`)**  
  - **May sign** non-CA keys (e.g., Document/Template signers) and/or CA/Intermediate (subject to the issuer’s own flags below).

### CA vs. End‑Entity
- If a cert has **any CA flag set** (`0x0001`, `0x0002`, `0x0004`), it **must not be used** directly as a **Document Signer** or **Template Signer**.
- If such a CA certificate sets `0x0100` and/or `0x0200` bits, interpret those bits **only** as authorization to issue certificates carrying those end‑entity bits, not as its own capabilities.

### End‑Entity Authorization
- For each end‑entity bit (`0x0100`, `0x0200`), if a subject certificate contains the bit, its issuer must also have that bit. Otherwise the signature is **policy‑invalid** even if cryptographically valid.

### Issuance Constraints
- Issuer must have `CA (0x0004)` to sign any certificate.
- Intermediate CA (`0x0002`) may sign only CA (`0x0004`) or Intermediate (`0x0002`) certificates.
- Child flags must be a subset of parent flags: `Child.Flags ⊆ Parent.Flags`.

---

## Chain validation algorithm

1. Verify structure and lengths.
2. Compute `KeyId` as `SHA-256(PubKey)[0..15]` and verify it matches the embedded value.
3. Build a path from leaf to a trusted root by matching `SignKeyId` to parent `KeyId`.
4. For each child/parent pair:
   - Parent must have CA bit (`0x0004`).
   - If parent has Intermediate bit (`0x0002`), child must be CA or Intermediate.
   - For each end‑entity bit (`0x0100`, `0x0200`): if child has it, parent must also have it.
   - Enforce `child.Flags ⊆ parent.Flags`.
5. Root with `0x0001` must be self-signed and present in the trust store.

---

## Ed25519 details (AlgVer = 0x01)
- **Public key:** 32 raw bytes (RFC 8032).
- **Signature:** 64 raw bytes (RFC 8032).
- **KeyId:** first 16 bytes of SHA-256 over the 32-byte public key.
- **Signature input:** exactly the TBS bytes (no pre-hash).

---

## Chain packaging (concatenation format)

To allow distributing an entire trust path as **one Base64 string**, a certificate may be followed **immediately** by another full certificate structure (starting again at **Magic**). You can therefore concatenate the whole trust tree (leaf → … → root) into one binary blob and **Base64‑encode the entire concatenation as a single string** (no separators).

### Encoding rules
- Each element is a complete **Certificate** as specified for the chosen `AlgVer`.
- Concatenate certificates **in order from leaf to root**. The final element SHOULD be a **Root CA** (`0x0001`) and MUST be self‑signed.
- After concatenation, **Base64‑encode the entire byte sequence** (standard Base64, no line breaks).
- This container is purely a packaging convenience; cryptographic validity is still per‑certificate.

### Parsing rules
- Decode Base64 once to obtain the binary blob.
- Starting at offset 0, parse a **Certificate**. Its **length** is determinable from its internal fields (notably `DescLen`, `UserDescCount` block, and `SigCount`).
- After finishing one certificate, **if there are remaining bytes**, the next byte MUST be `Magic` (`08 44 53`), and parsing continues for the next certificate.
- Continue until the end of the byte array. Reject if trailing bytes remain that do not begin with `Magic` or if any certificate is malformed.

### Validation
- Build chains using the **SignKeyId → KeyId** linkage between adjacent certificates. When a concatenated parent is present, it **must** match the `SignKeyId` of the child and validate per signature and policy rules.
- If a required issuer is **not** present in the concatenation, the validator MAY resolve it from a local trust store; however, when present, the concatenated parent MUST be used and must validate.
- All existing **policy rules** apply (self‑signed roots for `0x0001`, `CA` requirement to issue, subset‑of‑flags, end‑entity authorization, etc.).

### ABNF update
```
CertificateChain = 1*Certificate        ; one or more Certificates back-to-back
; Each Certificate is defined as previously for AlgVer = 0x01
; The entire CertificateChain is Base64-encoded when transported as text.
```
