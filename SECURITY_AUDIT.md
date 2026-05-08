# QLSA Security Audit — Phase 5 Results

Audit date: 2026-05-08  
Branch: `claude/review-repo-structure-E4kPW`  
Auditors: Cryptography Expert + Code Verification Expert (AI pair)

---

## Status Legend
- ✅ FIXED — resolved in this commit
- 📋 DEFERRED — documented, scheduled for a future MVP phase
- ℹ️  FALSE POSITIVE — claim is incorrect; no action needed

---

## CRITICAL FINDINGS

### C-1 — M31 Multiplication Soundness Gap
**Severity:** CRITICAL  
**Status:** 📋 DEFERRED → MVP-4  
**Files:** `mldsa_ntt_air.rs:110`, `mldsa_intt_air.rs:109`, `mldsa_poly_mul_air.rs:79`

Constraint C1 (multiplication mod Q) is evaluated in M31 arithmetic. Since
`ζ × b_in` can reach ~2^46 while M31 wraps at 2^31−1, the M31 equation
`ζ × b_in − t − carry_t × Q = 0 (mod M31)` does not guarantee the integer
equation. A malicious prover can craft `(t, carry_t)` satisfying C1 mod M31
while violating the integer reduction.

**Impact:** NTT, INTT, and PolyMul proofs are not cryptographically sound
against an adversarial prover. The system is sound for honest provers only.

**MVP-4 Fix:** Add range-check AIR arguments for all multiplication operands:
- Prove `a_in, b_in ∈ [0, Q)` via range-check columns
- Prove `t = ζ × b_in mod Q` with `carry_t ∈ [0, Q)` via range-check
- This closes the soundness gap entirely

---

### C-2 — Missing INTT N^{-1} Scaling Constraint
**Severity:** CRITICAL  
**Status:** 📋 DEFERRED → MVP-4  
**File:** `mldsa_intt_air.rs` (trace builder, after butterfly loop)

The final N^{-1} = 8,347,681 scaling step of the INTT (FIPS 204 Algorithm 42)
is applied in `build_trace()` but is NOT proved by any AIR constraint. The
commitment fingerprints the scaled output, but a malicious prover can commit to
an unscaled polynomial and the butterfly constraints will still pass.

**MVP-4 Fix:** Add a dedicated scaling column to the INTT AIR, or add a
separate `N_INV` multiplication AIR step. Alternatively, fold the scaling into
the last butterfly stage as a modified twiddle factor.

---

## HIGH FINDINGS

### H-1 — Weak Fiat-Shamir Binding (32-bit → 128-bit)
**Severity:** HIGH  
**Status:** ✅ FIXED (this commit)  
**Files:** `lib.rs` (all poly prove/verify functions), `mldsa_verify_stark.rs`

Previously, only a single 32-bit M31 word was mixed into the Fiat-Shamir
channel. Birthday collision on 32 bits requires only ~2^16 attempts, allowing
an adversarial prover to find an alternative output Y with `fingerprint(Y) ==
fingerprint(X)` and choose FRI queries favorably.

**Fix:** Replaced single-word mixing with 4-word (128-bit) `output_fingerprint`
for all polynomial circuits (NTT, INTT, PolyMul, PolyAdd). Birthday bound is
now ~2^64. New Scheme-B commitment encodes all 4 words; all 4 are mixed via
`channel.mix_u32s(&fp)`.

---

### H-2 — batcher.py commitment size mismatch
**Severity:** HIGH  
**Status:** ✅ FIXED (this commit)  
**File:** `aggregator/batcher.py`

`BatchResult.stark_commitment_onchain` expected 4 or 8 bytes but the Rust
library now returns 16-byte (32-hex-char) commitments. Any call to the property
would raise `ValueError: commitment must be 4 or 8 bytes, got 16`.

**Fix:** Updated property to accept exactly 16 bytes; updated the comment.

---

### H-3 — DoS via oversized proof deserialization
**Severity:** HIGH  
**Status:** ✅ FIXED (this commit)  
**File:** `lib.rs:MAX_PROOF_BYTES`

`MAX_PROOF_BYTES` was 32 MB. A malicious caller could submit a 32 MB proof,
causing ~32 MB heap allocation before any STARK verification work. In a
concurrent environment this enables OOM-based DoS.

**Fix:** Reduced to 8 MB (still 40–80× the typical proof size of 90–200 KB).

---

### H-4 — ABI commitment type mismatch in submit.py
**Severity:** HIGH  
**Status:** ✅ FIXED (this commit)  
**File:** `testnet/submit.py`

The inline ABI declared the `BatchFinalized` event commitment as `bytes8`
(Solidity V1 interface), while `BatchRegistryV2` actually emits `bytes16`
(V2 interface). This would cause incorrect event decoding in the submitter.

**Fix:** Updated ABI to `bytes16`. Also added validation in `submit_batch()` to
enforce exactly 16 bytes; added explicit error on wrong length.

---

### H-5 — Carry range not constrained in multiplication AIR
**Severity:** HIGH  
**Status:** 📋 DEFERRED → MVP-4  
**Files:** `mldsa_ntt_air.rs:154`, `mldsa_intt_air.rs:150`, `mldsa_poly_mul_air.rs:114`

`carry_t = floor(ζ × b_in / Q)` can be up to ~Q ≈ 8.3×10^6, but no upper
bound constraint exists in the AIR. Combined with C-1, a malicious prover has
a large choice of (t, carry_t) pairs satisfying C1 mod M31.

**MVP-4 Fix:** Constrain `carry_t ∈ [0, Q)` via range-check column. This
is part of the same MVP-4 range-check work as C-1.

---

## MEDIUM FINDINGS

### M-1 — INTT twiddle factor not bound to row index
**Severity:** MEDIUM  
**Status:** 📋 DEFERRED → MVP-4  
**File:** `mldsa_intt_air.rs` (witness generation)

The AIR verifies the butterfly arithmetic but does not constrain which twiddle
factor is used at each row. A malicious prover can supply arbitrary ζ^{-1}
values, and the constraint `ζ_inv × diff − b_out − carry_b × Q = 0` will pass
for a witness where b_out is adjusted to match the wrong ζ_inv.

**MVP-4 Fix:** Pre-compute the twiddle table as a preprocessed column and
enforce equality between the witness twiddle and the preprocessed value.

---

### M-2 — BatchRegistryV2.sol comments referenced wrong byte lengths
**Severity:** MEDIUM  
**Status:** ✅ FIXED (this commit)  
**File:** `contracts/src/BatchRegistryV2.sol`

Multiple comments described the commitment as "8-byte" and showed the formula
`Blake2s(...)[0:8]`, which matched the V1 QLSAVerifierFull scheme but not the
actual V2 (bytes16) scheme. Fixed all comments.

---

### M-3 — Az sub-proof linkage relies on STARK soundness only
**Severity:** MEDIUM  
**Status:** 📋 DEFERRED → MVP-4  
**File:** `mldsa_verify_stark.rs` (`prove_az`)

The pipeline generates independent proofs for NTT(z[j]) and A_hat[i][j]⊙z_hat[j].
There is no explicit cross-proof commitment linking the NTT output to the
PolyMul input; correctness relies entirely on STARK soundness preventing
inconsistent outputs. This is architecturally correct but weak.

**MVP-4 Fix:** Use a single compound AIR that proves all pipeline steps jointly,
or create an explicit Merkle commitment tree over sub-proof outputs.

---

### M-4 — Poseidon2 round constants are non-standard
**Severity:** MEDIUM (compliance risk only)  
**Status:** 📋 DEFERRED → future research  
**File:** `poseidon2.rs`

Round constants are derived from SHA-256 IV values rather than the standard
Poseidon2 constant generation procedure. The entropy is adequate but the
instantiation is not compliant with the Poseidon2 security proof.

**Future Fix:** Replace with the official Poseidon2-BN254 or Poseidon2-M31
parameter sets when they are published.

---

## LOW FINDINGS

### L-1 — H(a,b) = a³+b hash chain is not cryptographically secure
**Severity:** LOW  
**Status:** ℹ️ DOCUMENTED (known; `air.rs` comment already notes this)  
**File:** `air.rs`

The prototype algebraic hash chain uses `H(a,b) = a³+b`, which is not a secure
PRF. It is retained only for the basic `prove_hash_chain` MVP-2 path. All
production paths use Poseidon2 or the ML-DSA batch verifier.

**Action:** Do NOT use `prove_hash_chain` in any testnet/mainnet deployment;
always use `prove_hash_chain_poseidon2` or `prove_mldsa_batch`.

---

### L-2 — Private key material not zeroized in Rust FFI
**Severity:** LOW  
**Status:** 📋 DEFERRED → MVP-4  
**File:** `mldsa/verify.rs`

`ml_dsa_verify()` accepts pk/sig as slices but does not guarantee these are
zeroed after use. Python's `wipe_key()` wrapper exists but GC is not guaranteed.

**MVP-4 Fix:** Add `zeroize` crate dependency; use `Zeroizing<Vec<u8>>` wrappers
for pk/sig in the Rust boundary.

---

### L-3 — Missing HTTPS enforcement in Python HTTP client
**Severity:** LOW  
**Status:** 📋 DEFERRED → pre-testnet  
**File:** `sdk/python/qlsa/client.py`

`HttpClient` uses plain HTTP without enforcement. In a testnet/mainnet
environment, all RPC endpoints should be HTTPS.

**Pre-testnet Fix:** Validate that `rpc_url` starts with `https://`; document
that HTTP is allowed only for local dev nodes.

---

### L-4 — Incomplete ML-DSA.Verify circuit (by design)
**Severity:** LOW  
**Status:** 📋 DEFERRED → MVP-3+/MVP-4  
**File:** `mldsa_verify_stark.rs`

`prove_az` proves the matrix-vector product Az but not the full ML-DSA.Verify
algorithm (norm checks, UseHint, w1 encoding, hash comparison). This is the
current scope of MVP-3+.

**MVP-3+/MVP-4 Fix:** Add `prove_ct1`, `prove_norm_check`, and `prove_hash_verify`
as additional STARK sub-proofs to cover the full FIPS 204 Algorithm 3.

---

## FALSE POSITIVES IN AUDIT

### FP-1 — "Q > M31" claim is incorrect
**File:** Various (flagged by cryptography auditor)

Claim: `BaseField::from_u32_unchecked(Q as u32)` is undefined behavior because
Q > M31.

**Verdict: FALSE POSITIVE.** Q = 8,380,417 and M31 = 2,147,483,647. Since
Q << M31, the cast is well-defined and correct. No action needed.

---

## SUMMARY TABLE

| ID  | Severity | Status          | Description                                   |
|-----|----------|-----------------|-----------------------------------------------|
| C-1 | CRITICAL | 📋 MVP-4        | M31 multiplication soundness gap              |
| C-2 | CRITICAL | 📋 MVP-4        | Missing INTT N⁻¹ scaling constraint          |
| H-1 | HIGH     | ✅ FIXED        | Weak 32-bit Fiat-Shamir binding → 128-bit    |
| H-2 | HIGH     | ✅ FIXED        | batcher.py commitment size mismatch           |
| H-3 | HIGH     | ✅ FIXED        | DoS via 32 MB proof deserialization limit     |
| H-4 | HIGH     | ✅ FIXED        | ABI bytes8→bytes16 mismatch in submit.py      |
| H-5 | HIGH     | 📋 MVP-4        | Carry range unconstrained in mul AIR          |
| M-1 | MEDIUM   | 📋 MVP-4        | INTT twiddle factor not row-bound             |
| M-2 | MEDIUM   | ✅ FIXED        | BatchRegistryV2.sol stale "8-byte" comments   |
| M-3 | MEDIUM   | 📋 MVP-4        | Az sub-proof pipeline linkage is implicit     |
| M-4 | MEDIUM   | 📋 Future       | Non-standard Poseidon2 round constants        |
| L-1 | LOW      | ℹ️ Known        | H(a,b)=a³+b is not cryptographically secure  |
| L-2 | LOW      | 📋 MVP-4        | Private key not zeroized at Rust FFI          |
| L-3 | LOW      | 📋 Pre-testnet  | No HTTPS enforcement in SDK client            |
| L-4 | LOW      | 📋 MVP-3+/MVP-4 | ML-DSA.Verify circuit is partial by design    |

---

## Security Posture for Current Phase (MVP-3+)

The system is **SUITABLE for local development and research** but **NOT suitable
for mainnet deployment** due to the two CRITICAL findings (C-1, C-2).

For **testnet deployment** (Phase 6), the following conditions must be met:
1. ⚠️ The testnet verifier must be explicitly scoped as a non-production
   prototype; on-chain comment should state the soundness limitations.
2. ✅ H-1 through H-4 are now fixed.
3. ✅ The FRI blowup factor (LOG_BLOWUP=4, 120-bit security) is sufficient for
   a research testnet but must be increased to ≥8 before mainnet.
4. ⚠️ Test wallet `0xBFb32E28c22505c34520e3B0830E6789F1943e3f` private key was
   exposed in prior session chat history and MUST NOT be used for mainnet.
   Generate a fresh wallet for any real-value deployment.
