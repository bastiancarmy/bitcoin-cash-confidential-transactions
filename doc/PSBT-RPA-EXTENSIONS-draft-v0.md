# PSBT RPA Extensions (Phase 1.5 – PSBT / HW Mapping, Draft v0)

> **Status: DRAFT / INTERNAL / EXPERIMENTAL – v0**  
> This is an internal sketch for Phase‑1.5 of the RPA + confidential‑asset demo.  
> It is **not a stable standard**, may change without notice, and is intended
> only to guide prototype implementations and discussion.
>
> In this v0 draft:
> - Only **`rpa_context` (subType = 0x01)** is considered part of the minimal,
>   experimental mapping.
> - `proof_hash` (0x02) and `zk_seed` (0x03) are **reserved for future phases**
>   (Phase‑2 / ZK) and **do not yet form a stable contract** for hardware or
>   other external signers.

Scope: BCH + RPA demo (PZ‑SQH), Phase‑1.5 (PSBT / HW mapping).

The goal of this draft is to sketch how a PSBT can carry **RPA derivation
context** so that an offline signer can deterministically re‑derive the
one‑time child key for an output, **without**:

- scanning the blockchain,
- backing up random “ephemeral” secrets, or
- tagging on‑chain outputs (no OP_RETURN beacons, no script prefixes).

All RPA “ephemeral” keys remain deterministic children of:

- the seed (paycode scan/spend secrets), plus
- on‑chain data (sender pubkey, outpoint, index).

The PSBT extension carries only the derivation context, not the derived keys.

---

## 1. PSBT proprietary prefix

We use PSBT’s `proprietary` key type (`0xFC`) with a project‑specific,
**temporary** prefix.

- **Key type**: `0xFC` (proprietary, per BIP‑174)
- **Prefix** (ASCII): `bch-rpa-v0`  
  - Length: 10 bytes  
  - **Provisional name** for this demo; can be renamed in a future revision.

For any proprietary entry in a PSBT map (global, input, or output), the key
format is:

```text
key = 0xFC || prefixLen || prefix || subType || keyData...

where:
  - 0xFC       = proprietary type
  - prefixLen  = 1-byte length of `prefix` (here: 0x0A)
  - prefix     = ASCII "bch-rpa-v0"
  - subType    = 1-byte subtype ID for this project
  - keyData    = optional extra key data (unused in v1)
```

For this phase we only use **output‑level** proprietary fields (PSBT_OUT
maps). The `keyData` portion is empty – each output can have at most one
entry for a given `(prefix, subType)` pair.

---

## 2. Subtypes and semantics

Subtypes under the `bch-rpa-v0` prefix:

- `0x01` – **RPA context** (`rpa_context`) – **v0 minimal mapping**
- `0x02` – **proof hash** (`proof_hash`) – reserved for future ZK phases
- `0x03` – **ZK seed / session ID** (`zk_seed`) – reserved for future ZK phases

All three live in the **output map** for the corresponding transaction output,
but **only `0x01` is required / meaningful in v0**.

### 2.1 RPA context (`subType = 0x01`) – v0 core

The RPA context tells a signer **how to deterministically reconstruct the
one‑time child key** for a given output. For v1 we keep this fixed‑size and
simple:

```c
// Value: 77 bytes total
struct RpaContextV1 {
    uint8_t  version;         // = 0x01
    uint8_t  mode;            // RPA mode enum (e.g. stealth-p2pkh, pq-vault, conf-asset)
    uint8_t  reserved1;       // must be 0x00
    uint8_t  reserved2;       // must be 0x00
    uint32_t index_le;        // RPA child index (LE)
    uint32_t prevout_vout_le; // funding input vout (LE)
    uint8_t  prevout_txid[32];// funding input txid, big-endian as printed
    uint8_t  sender_pubkey[33];// compressed secp256k1 pubkey
};
```

- `version` – payload version for the context; v1 = `0x01`.
  - If a signer sees an unsupported version, it **must refuse to sign**.
- `mode` – small integer identifying the RPA “mode” used when deriving this
  child key (e.g. 1 = stealth‑p2pkh, 2 = pq‑vault, 3 = confidential‑asset).
  - Exact mapping is defined in the CLI / demo code, not in this doc.
- `index_le` – the derivation index used as part of the RPA function.
- `prevout_vout_le` – the `vout` of the **funding input** outpoint.
- `prevout_txid` – the **funding input txid**, big‑endian, 32 bytes.
- `sender_pubkey` – 33‑byte compressed pubkey of the RPA “sender” for this
  child (e.g. the funding wallet key for this flow).

Combined with the signer’s own paycode scan/spend secrets (tied to the seed)
and the project’s RPA derivation rules, this is enough to re‑derive the child
key that controls this output.

**Note:** `paycodeId` is *not* included in v1. If we later decide we need a
stable paycode identifier, we can either:

- Add a v2 struct with a trailing `paycode_id` field; or
- Use a new subtype under the same prefix.

### 2.2 Proof hash (`subType = 0x02`) – reserved for Phase‑2

> **Not part of the v0 minimal mapping.**  
> Documented here only as a placeholder for future confidential‑asset / ZK
> flows.

Intended use: store the hash of the confidential‑asset proof envelope for this
output.

- Value: `proof_hash` – 32 bytes
- Encoding: raw bytes, no framing.

In Phase‑1 this corresponds to `proofHash = hash256(envelope)` in the demo,
but hardware wallets **must not rely on this field yet** – its semantics and
even existence may change in Phase‑2.

### 2.3 ZK seed / session ID (`subType = 0x03`) – reserved for Phase‑2

> **Not part of the v0 minimal mapping.**  
> Documented as a possible future way to bind a proof transcript back to an
> RPA session.

Intended use: store the **ZK seed / session ID** used when generating the
proof, tying the proof transcript back to the same RPA session without
introducing new secrets beyond the seed + chain.

- Value: `zk_seed` – 32 bytes
- Encoding: raw bytes, no framing.

In the current demo this is the `zkSeed` already present in the RPA session
object, but again: hardware wallets **must not assume** this field is stable
until the Phase‑2 design is finalized.

---

## 3. Where fields live in PSBT

For each transaction output that is controlled by an RPA‑derived child key,
the PSBT **output map** (PSBT_OUT) may contain proprietary entries under the
`bch-rpa-v0` prefix.

In v0, the only required / meaningful field is:

- `bch-rpa-v0 / 0x01` → RPA context (`RpaContextV1`)

Future phases *may* also use:

- `bch-rpa-v0 / 0x02` → `proof_hash` (32 bytes, reserved)
- `bch-rpa-v0 / 0x03` → `zk_seed` (32 bytes, reserved)

Pseudocode using a Bitcoin‑style PSBT representation:

```js
// For output i (v0 minimal mapping):
output.unknownKeyVals.push({
  key:   <0xFC || 0x0A || "bch-rpa-v0" || 0x01>,
  value: encodeRpaContextV1(context)
});

// Future phases (optional, NOT stable in v0):
output.unknownKeyVals.push({
  key:   <0xFC || 0x0A || "bch-rpa-v0" || 0x02>,
  value: proofHash32
});

output.unknownKeyVals.push({
  key:   <0xFC || 0x0A || "bch-rpa-v0" || 0x03>,
  value: zkSeed32
});
```

A hardware wallet that understands this draft extension (v0):

1. Locates proprietary keys with prefix `bch-rpa-v0` and `subType = 0x01`,
2. Parses the `RpaContextV1` struct from that value,
3. Uses its seed to re‑derive the RPA child key for that output, and
4. Signs the PSBT using that derived key as if it were a normal HD child.

Any additional subtypes (`0x02`, `0x03`, or future IDs) must be treated as
**optional hints only** until a later spec revision promotes them to stable
status.

---

## 4. Example (conceptual)

Suppose we have an RPA‑derived output with:

- `mode` = `3` (confidential‑asset demo)
- `index` = `0`
- `prevout_txid` = `f950...506` (32 bytes, BE)
- `prevout_vout` = `0`
- `sender_pubkey` = `02ef03...1e55b` (33‑byte compressed)

Then the output’s PSBT map will include, at minimum:

```text
// RPA context (subType 0x01)
key   = 0xFC 0x0A "62 63 68 2d 72 70 61 2d 76 30" 0x01
value = 77-byte RpaContextV1 payload
```

Optionally (future phases), it *may* also include proprietary entries for
`proof_hash` (0x02) and `zk_seed` (0x03), but those are not required or
stable in v0.

The exact hex for `value` will depend on the concrete values and encoder, but
the structure is fixed by this draft.

---

## 5. Security and recovery properties (design goals)

The v0 mapping is designed to preserve the core RPA / HD properties:

- **No chain scanning on hardware:** the signer never has to guess or scan
  arbitrary outputs. It only derives RPA children for outputs explicitly
  tagged in the PSBT with this extension.
- **No extra backups:** all “ephemeral” child keys are deterministically
  derived from the seed + on‑chain context. There are no separate secrets to
  store, sync, or export.
- **HD‑style recovery:** seed + blockchain are sufficient to reconstruct the
  entire stealth tree. The PSBT extension simply makes that derivation
  explicit and portable to hardware signers and other off‑chain tools.
- **Forward‑compatible:** future versions can:
  - Add new subtypes under the same prefix, or
  - Bump `version` in the RPA context struct while keeping the existing
    subtype ID.

As this is a **draft**, any implementation should treat this doc as
“implementation guidance”, not a finalized standard. Future revisions may
change field layouts, prefix naming, or subtype semantics as the ZK / pool
design stabilizes.

---

## 6. Reference helper module

A reference helper module (e.g. `src/psbt_rpa.js`) is expected to:

- Encode/decode `RpaContextV1` to/from PSBT proprietary values.
- Provide helpers for pulling `RpaContextV1` out of PSBT output maps.
- Optionally, handle `proof_hash` and `zk_seed` as best‑effort fields, but
  only as **experimental / non‑stable** data.

Implementations should clearly label any user‑facing support for this
extension as **experimental** and be prepared to migrate if the format
changes in future phases.
