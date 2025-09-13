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
- Implementations **must not** modify the `Flags` field when re‑emitting a certificate. Any reserved bits present in input data
  **must be preserved** exactly to avoid altering signed bytes.

---

## Flag semantics and policy

### Roles and combinations
- **Root CA (`0x0001`)**
  - **Must be self‑signed.**
  - May also carry `INTERMEDIATE_CA (0x0002)` and/or `CA (0x0004)`.
  - The ability to sign depends on the presence of `INTERMEDIATE_CA` and/or `CA` flags (see signing rules below), not on `ROOT_CA` alone.

- **Intermediate CA (`0x0002`)**
  - Authorized to sign only certificates that carry CA‑level flags (`INTERMEDIATE_CA` or `CA`).
  - Not authorized to sign non‑CA certificates unless it also carries `CA` (see combined case below).

- **CA (`0x0004`)**
  - Authorized to sign only non‑CA certificates (no `ROOT_CA`, `INTERMEDIATE_CA`, or `CA` flags on the subject).
  - Not authorized to sign CA‑level certificates.

- **Combined `INTERMEDIATE_CA | CA`**
  - Authorized to sign both CA‑level certificates (because of `INTERMEDIATE_CA`) and non‑CA certificates (because of `CA`).

- **No CA flags**
  - Cannot sign any certificates.

### End‑entity flags (non‑CA) inheritance
- End‑entity flags are the non‑CA bits (e.g., `DOCUMENT_SIGNER (0x0100)`, `TEMPLATE_SIGNER (0x0200)`).
- A subject’s end‑entity flags must be a subset of its issuer’s end‑entity flags:
  - `Subject.EndEntityFlags ⊆ Issuer.EndEntityFlags`.

### Signing rules matrix
- To sign a subject with any CA‑level flag (`ROOT_CA`, `INTERMEDIATE_CA`, or `CA`): the issuer must have `INTERMEDIATE_CA`.
- To sign a subject with no CA‑level flags (a pure end‑entity): the issuer must have `CA`.

Quick reference:

| Issuer flags                | Sign non‑CA subject | Sign CA‑level subject |
|----------------------------:|:-------------------:|:---------------------:|
| None                        | ✗                   | ✗                     |
| CA                          | ✓                   | ✗                     |
| INTERMEDIATE_CA             | ✗                   | ✓                     |
| INTERMEDIATE_CA | CA        | ✓                   | ✓                     |

Notes:
- Presence of `ROOT_CA` does not by itself grant signing capability; it only asserts root identity and must be self‑signed. Combining `ROOT_CA` with the rows above does not change the ✓/✗ outcomes.
- End‑entity flags must obey subset inheritance: `Subject.EndEntity ⊆ Issuer.EndEntity`.

### End‑Entity Inheritance Matrix
Only illustrates the subset rule for end‑entity flags. CA‑level signing capability (issuer must have `CA` for non‑CA subjects, `INTERMEDIATE_CA` for CA‑level subjects) still applies separately.

Legend: Document = `0x0100`, Template = `0x0200`.

| Issuer end‑entity flags | Subject: None | Subject: Document | Subject: Template | Subject: Document+Template |
|------------------------:|:-------------:|:-----------------:|:-----------------:|:-------------------------:|
| None                    | ✓             | ✗                 | ✗                 | ✗                         |
| Document                | ✓             | ✓                 | ✗                 | ✗                         |
| Template                | ✓             | ✗                 | ✓                 | ✗                         |
| Document+Template       | ✓             | ✓                 | ✓                 | ✓                         |

Reminder: This matrix validates only the end‑entity subset requirement. The issuer must still have the appropriate CA‑level flag to sign the subject at all (see the Signing rules matrix above).

Notes
- A certificate with `ROOT_CA` must be self‑signed, but it may also carry `INTERMEDIATE_CA` or `CA` (or both).
- The presence of CA‑level flags does not prevent a certificate from also carrying end‑entity flags; those end‑entity bits govern what end‑entity flags it may delegate to subjects, not necessarily whether it acts as an end‑entity itself.

---

## Chain validation algorithm

1. Verify structure and lengths.
2. Compute `KeyId` as `SHA-256(PubKey)[0..15]` and verify it matches the embedded value.
3. Build a path from leaf to a trusted root by matching `SignKeyId` to parent `KeyId`.
4. For each child/parent pair (issuer = parent):
   - If child is CA‑level (has any of `ROOT_CA`, `INTERMEDIATE_CA`, `CA`): issuer must have `INTERMEDIATE_CA`.
   - If child is non‑CA (no CA‑level flags): issuer must have `CA`.
   - End‑entity inheritance: For each end‑entity bit (`0x0100`, `0x0200`), if child has it, issuer must also have it (`Child.EndEntity ⊆ Issuer.EndEntity`).
5. A certificate with `ROOT_CA` must be self‑signed and present in the trust store.

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
