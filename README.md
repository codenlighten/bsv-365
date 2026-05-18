# bsv-365

A hardened, drop-in fork of [`bsv@1.5.6`](https://github.com/moneybutton/bsv) that preserves the full public API while patching known cryptographic-dependency CVEs and adding defense-in-depth signature validation.

Use this if you depend on the `bsv@1.x` interface but want the security posture of a maintained library. The upstream `bsv@2.x` rewrite changes the API surface; this fork does not.

## What changed vs. upstream `bsv@1.5.6`

### Dependency upgrades
| Dep        | bsv@1.5.6 | bsv-365   | Fixes |
|------------|-----------|-----------|-------|
| `elliptic` | `6.5.4`   | `^6.6.1`  | CVE-2024-48948, CVE-2024-48949, CVE-2024-48951 (signature malleability, DER parsing, length checks) |
| `bn.js`    | `=4.11.9` | `^4.12.3` | GHSA-378v-28hj-76wf (infinite loop) |

### In-library hardening
- **`lib/crypto/signature.js`**
  - `parseDER` rewritten with full bounds checking, BIP66 strict mode, and rejection of negative / zero / excessively-padded R and S — even in non-strict mode (i.e. you can no longer crash the parser with a malformed buffer).
  - New `Signature.isStrictDER(buf)` predicate.
  - New `Signature.prototype.toLowS()` to canonicalize a signature into its low-S form (defeats third-party malleability).
  - `Signature.fromCompact` now validates buffer length and rejects zero R/S.
  - `Signature.SECP256K1_N` exported for convenience.
- **`lib/crypto/ecdsa.js`**
  - `sigError` adds BN-type validation, pubkey-presence, and explicit not-at-infinity checks.
  - New `strict` flag on the `ECDSA` instance that rejects high-S signatures (BIP62 / consensus-style standardness).
  - New static `ECDSA.verifyStrict(hashbuf, sig, pubkey, endian)` — **recommended for new code**.
- **`lib/crypto/point.js`** — unchanged; the existing `Point.validate()` already enforces on-curve + correct subgroup (`n·P = ∞`), which is the deeper guard against the residual elliptic advisory (GHSA-848j-6mx2-7j84, no upstream fix).

### Public API: unchanged
Existing call sites work as-is:

```js
const bsv = require('bsv-1.5.6-hardened')
const priv = bsv.PrivateKey.fromRandom()
const sig  = bsv.crypto.ECDSA.sign(hash, priv)
const ok   = bsv.crypto.ECDSA.verify(hash, sig, priv.publicKey)
```

All new functionality is additive. Nothing has been renamed or removed.

## Install

```bash
npm install bsv-1.5.6-hardened
```

Or directly from this repo:

```bash
npm install codenlighten/bsv-365
```

## Recommended usage in new code

```js
const { ECDSA, Signature } = bsv.crypto

// Reject high-S (malleated) signatures during verification:
const ok = ECDSA.verifyStrict(hash, sig, pubkey)

// Canonicalize a signature you received from elsewhere:
const canonical = sig.toLowS()

// Validate a raw DER buffer before parsing:
if (!Signature.isStrictDER(buf)) throw new Error('bad signature encoding')
```

## Testing

```bash
npm test
```

Smoke tests cover sign/verify round-trips, tampered inputs, high-S malleability handling, strict DER parsing (positive and negative cases), compact-signature validation, and end-to-end P2PKH transaction signing.

## Residual advisories

`npm audit` will still report **GHSA-848j-6mx2-7j84** against `elliptic` — a design-level "risky primitive" advisory with no upstream fix planned. The in-library hardening (strict DER parsing, low-S enforcement, full `Point.validate()`) is the mitigation: untrusted bytes never reach `elliptic` without being canonicalized and bounds-checked first.

## License

MIT — same as upstream bsv. See `LICENSE-bsv` for the original copyright notice.
