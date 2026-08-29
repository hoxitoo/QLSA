# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

*That is the architecture. What the code proves today is narrower — read the box
below before relying on any claim here.*

---

> **⚠ NOT PRODUCTION READY — Research Prototype**
>
> This codebase is a **research prototype / testnet demonstrator**. It has **not**
> undergone an external cryptographic audit.
>
> ### What the on-chain proof does and does not establish
>
> Read this before treating any number in this repository as a security claim.
>
> **It establishes:** the ML-DSA-65 *arithmetic* relations hold for a committed
> witness — `w' = A·z − c·t1·2^d` computed through NTT/INTT, `‖z‖∞ < γ₁−β`, the
> hint decompression and the ω bound, and range membership — proved by a Circle
> STARK at 130-bit FRI soundness and verified in one Ethereum transaction.
>
> **It does NOT establish that a signature exists.** The FIPS 204 hash step —
> `c̃ = SHAKE-256(μ ‖ w1Encode(w1'))` and `c = SampleInBall(c̃)` — is **outside the
> circuit**. `c̃` is bound into the Fiat-Shamir transcript, but nothing in the
> constraint system ties it to `w1'`. A prover who picks a small-norm `z`, any
> valid-shaped `c`, and their own `t1` can satisfy every constraint with no
> signature involved. Closing this needs SHAKE-256 (Keccak-f[1600]) arithmetized
> as an AIR; that work is **not started and not scheduled** — see limitation 2.
>
> In the shipped pipeline the prover *does* run a full `ml_dsa_verify` in Rust
> before extracting the witness and refuses invalid signatures, so an honest
> aggregator cannot prove a forgery. But that check is **off-chain and
> unverifiable by the contract** — the on-chain verifier trusts the prover ran it.
>
> **What the deployed contracts enforce covers ONE signature per batch, not N.**
> `testnet/e2e.py` and `aggregator/batcher.py` generate the ML-DSA witness proof
> for `tx[0]` only. The remaining transactions are committed by the batch Merkle
> root but their signatures are not proved. The separate `prove_mldsa_batch` path
> verifies N signatures *in Rust* and proves only a hash chain over the results.
>
> **N-signature aggregation now works off-chain** (2026-08-27):
> `stark.prover.prove_mldsa_aggregation_tree` folds N ML-DSA-65 signatures into
> ONE root proof — four real signatures verified end to end. Two things separate
> that from the claim on the tin, and both are open:
> **(a)** no contract accepts a tree root yet, so nothing on-chain consumes it;
> **(b)** the root proves N signatures were verified *under* a batch root, not
> that they are that root's *members* — the batch root is a Fiat-Shamir binding,
> not a membership proof (`docs/TECH_DEBT.md` § A-5). Wiring the root on-chain
> without (b) would ship a contract whose guarantee is weaker than its interface
> reads.
>
> Until both gaps are closed, the headline above describes the **architecture**,
> not a property the deployed contracts enforce.
>
> ### Other known limitations
>
> - Off-chain STARK: `LOG_BLOWUP=6`, `N_FRI_QUERIES=20`, `POW_BITS=10` → 130-bit FRI soundness.
> - Two production bounds are **not reachable together** today: the recursive v8 stack
>   gives 130-bit FRI but ~2^62 Merkle nodes; `QLSAVerifierVFRI12` gives ~2^124 nodes
>   but 16-bit FRI (`n_queries=1`; 2 queries already exceed the per-tx cap).
> - `MAX_SENDERS = 3000` is declared in all six registries but is **not reachable**:
>   the O(n²) duplicate-sender scan makes ~200 the practical limit on `BatchRegistryV5`
>   and fewer on `BatchRegistryV7`, and exceeding it gives OUT OF GAS rather than a
>   clean `SenderCountExceedsLimit`. `submitBatch` (without nonces) has no such loop.
> - ~~The `aggregator`, HTTP API and both SDKs emit VFRI7–VFRI10 proofs, which the
>   default registry rejects by design.~~ **Closed (2026-07-31):** a protocol is now
>   selected by name (`stark.prover.WITNESS_PROTOCOLS`), the default follows the
>   deployed stack, and `recursive` is included — so the aggregator can emit either
>   the direct v7 stack or the recursive v8 stack at 130-bit soundness. The API
>   reports which registry shape each proof targets.
> - No public-testnet run: verified against a standalone JSON-RPC node only.
> - `/batch/run` and `/batch/flush` support Bearer-token auth via `QLSA_API_TOKEN`;
>   unset = open (research default — set it on any non-local deployment).
>

---

## Public testnet run (Sepolia)

Everything below is ready to run; it has not been exercised on a public network
because outbound RPC is blocked in the development environment. It HAS been run
end to end against a standalone JSON-RPC node: real ML-DSA-65 signatures through
V23 → VFRI11 at 20 queries → recursion → `BatchRegistryV7`, finalized in one
transaction at **13,168,471 gas**.

### 0. What you need

- An RPC endpoint. The public node in `.env.example` works but rate-limits, and a
  13M-gas submission is not a small request — use Infura/Alchemy/self-hosted.
- An account with Sepolia ETH. One submission is ~13.2M gas; **0.5 ETH** is ample
  for deployment plus several runs. Any Sepolia faucet will do.
- Rust nightly `2025-07-01`, Python 3.11+, Node 18+.

### 1. Configure

```bash
cp .env.example .env
```

Set in `.env`:

```
PRIVATE_KEY=0x<key of the funded account>       # hardhat reads THIS name
DEPLOYER_PRIVATE_KEY=0x<the same key>           # submit.py accepts either
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<your-key>
RPC_URL=https://sepolia.infura.io/v3/<your-key> # used by e2e.py / submit.py
```

`SEPOLIA_RPC_URL` overrides `RPC_URL` for `--network sepolia` only. Setting both
to the same endpoint is the simple choice.

### 2. Build

```bash
cd contracts && npm install && cd ..
cd stark_stwo && maturin develop --features python --release && cd ..
```

The PyO3 extension is required — without it the prover degrades to unproven mode
and `--dry-run` will tell you so rather than failing silently.

### 3. Rehearse without spending gas

```bash
python -m testnet.e2e --stack v8 --txs 4 --dry-run
```

This runs the whole path up to submission: keypairs, signatures, batch, Merkle
root, V23 witness, recursion. Expect proof sizes near `hints 10976 B` (LOG=10)
and `9760 B` (LOG=8), and a line reporting 130-bit soundness. If this fails, the
problem is local and no gas was spent finding out.

### 4. Deploy

```bash
bash testnet/deploy_v8.sh --network sepolia
```

Deploys `QLSAVerifierVFRI11` + `QLSAVerifierRecursive` + `BatchRegistryV7` and
writes the addresses to `.env.deployed` (mode 0600). Then:

```bash
cat .env.deployed >> .env
```

### 5. Submit

```bash
set -a && . ./.env && set +a
python -m testnet.e2e --stack v8 --txs 4
```

`--stack v8` raises FRI queries to 20 on its own if you leave the default — at
one query the recursive route costs more gas than direct verification for 16-bit
soundness, so it refuses to run pointlessly.

### 6. What to check

- `gasUsed` around **13.2M**. Materially higher means something is off — compare
  against `contracts/test/fixtures/measurements.json`, which the test suite
  re-measures.
- `finalized=True` and a `BatchFinalized` event. `python -m testnet.monitor`
  follows the event stream.
- On a registry-shape mismatch you get a clear error from `require_registry_kind`
  before the transaction, not an opaque revert inside it.

### If it fails

- **`SenderNonceTooLow`** — the registry stores 0 for an unseen sender and
  requires `newNonce > stored`, so the smallest submittable nonce is 1.
  `testnet.e2e.build_sender_nonces()` handles the mapping; if you submit through
  your own code, do the same.
- **`nonce too low` before the call** — the account had transactions mined
  between reading the counter and sending. The submitters read from `"pending"`
  for this reason; a custom submitter should too.
- **Out of gas above ~200 senders** — known, see `docs/TECH_DEBT.md` A-3. The
  `MAX_SENDERS = 3000` constant is not reachable.

---

## The Problem

Post-quantum cryptography is inevitable — but it breaks blockchain scalability.

| Signature | Size | 3000 tx block |
|----------|------:|--------------:|
| ECDSA (current) | ~70 bytes | ~220 KB |
| ML-DSA-65 (FIPS 204) | ~2,420 bytes | ~7.2 MB |

A direct migration causes **~30–40x overhead per block**, collapsing throughput.

> The bottleneck is not cryptography — it is infrastructure.

**Where this is going, and what could stop it: [`ROADMAP.md`](ROADMAP.md).** It
carries the measured economics — including the finding that inside a transaction's
gas limit the system does not currently break even at *any* N, because per-sender
nonce writes, not the proof, both eat the saving and set the ceiling.

---

## The Solution

QLSA is **not a new signature scheme**.

It is a **post-quantum aggregation layer** that makes PQ signatures usable at scale.

- Aggregate **N** ML-DSA signatures
- Produce **1 STARK proof** of constant size (~90–200 KB)
- Verify on-chain at O(1) cost

---

## Properties

- O(1) on-chain verification
- No trusted setup (FRI-based STARK)
- Post-quantum secure (lattice + hash)
- Deployable as L2 (no hard fork required)
- Crypto-agile (algorithm versioning supported)

---

## Current Status

**Recursion: measured, closed, and correctly sequenced** (2026-07-30, R4.10–R4.16). The recursion's verification contour is complete — `compValue` is pinned in-circuit and Merkle-bound to the inner proof's committed composition tree (R4.10/R4.12), and `BatchRegistryV7` finalizes a batch from two cross-bound recursive bundles in one transaction. The strategic finding is about *when* recursion pays: measured against direct verification at production depth/folds, direct grows linearly and hits the per-transaction cap at 8 FRI queries, while the recursion grows ~+0.5M per doubling — **break-even at ~2 queries** (q=4: 8.96M direct vs 5.93M recursive; q=8: 16.47M vs 6.45M). Since the current demo config is 1 query (16-bit on-chain soundness) and production security needs 20, **recursion is what makes production soundness reachable at all, not a gas saving at the demo config**. Three measurement errors preceded that conclusion — a `gasLimit` above 2^24 is rejected before execution, `estimateGas` over-provisions nested calls ~3×, and a parameter tuned for a small scale (`outer_folds=2`) became the dominant cost term at a large one, which alone made recursion look 2.7× more expensive than it is. Written up in `docs/conclusions.md`.

**Audit R4.8–R4.9** (2026-07-30). Crypto + code review of the newly added layer. The lazy-reduction claim underpinning the Poseidon2 rewrite was verified empirically rather than argued: a Python model mirroring the Solidity byte-for-byte was run against a fully-reduced reference over 3005 inputs (including the maximal reachable 2^32−1, exactly `P`, and `P±1`) — **0 mismatches**, peak intermediate magnitude 2^32 / 2^90 / 2^75 for t=2/4/8 against a 2^256 ceiling (2^165 headroom), confirming the in-code bounds are valid upper bounds. Findings fixed: **(a)** the Poseidon2 sponge cross-checks covered only rate-multiple lengths, leaving the hand-rewritten odd-tail padding branch pinned on neither side — closed with authoritative Rust vectors for every tail residue on both sides (t=8 n=1..12, t=4 n=1..8); **(b)** the new registry-shape probe swallowed transport errors via `except Exception`, so an RPC outage was read as "not a V6" and let a mismatched submit proceed — narrowed to contract-level exceptions only, verified against a live node; **(c)** `MAX_SENDERS = 3000` is unreachable — the O(n²) duplicate-sender scan costs ~201 gas/n², so n=3000 would need ~1821M gas (108× the cap) and the real limit is ~212, with *out of gas* rather than a clean revert; documented with the measured table across all five registries plus a regression test. Also: CI caught that a new test needed `web3` (in `requirements-testnet.txt`, which CI does not install) — it had passed locally only because the env was polluted. Verified clean: no secrets tracked, deliberate broad excepts in the aggregator's prover-crash recovery, SDK HTTP timeouts present, nonce mapping injective and monotonic. Known gap at the time, since **closed** (2026-07-31): `aggregator/` supported VFRI7–VFRI10 but not VFRI11, so it lagged the now-default stack — protocols are now selected by name and the default tracks the deployed stack. Details in `context.md`.

**Gas barrier removed — full on-chain verification in ONE transaction** (2026-07-30, R4.8). Every previously recorded "gas wall" turned out to be Poseidon2 *implementation* overhead in Solidity, not a property of the protocol: a t=8 permutation cost ~106k gas while its field arithmetic is ~3k, the rest being `uint256[8] memory` plumbing and a branchy conditional subtract on every linear-layer addition. Rewriting `Poseidon2M31T8`/`Poseidon2M31T4` with the state on the stack and **lazy modular reduction** (exact — add/mul mod P are ring homomorphisms and every S-box `mulmod` reduces its own output) cut per-permutation cost ~3.5×, with bit-exactness guaranteed by the 47 existing cross-check tests against the frozen Rust reference vectors (Rust unchanged). Measured `gasUsed`: **full `verifyRecursive` 2.29M (`ok=true`)**, **VFRI11 (t=8) dual `submitBatch` 6.06M in one tx** (was >100M / unverifiable), **VFRI10 (t=4) dual `submitBatch` 3.74M in one tx** (was ~18.5M, which is why `BatchRegistryV6` split it across two). Two measurement errors had made the walls look insurmountable: a `gasLimit` above 2^24 is rejected *before execution* (EIP-7825 cap), so the honest path had never actually run; and `estimateGas` over-provisions nested calls by ~3× — measure `gasUsed` of a sent transaction. Consequence: **t=8 (node collision ~2^62) is production-deployable in a single transaction**, a soundness upgrade over the t=4 stack, and the recursion's on-chain contour is closed with ~7× headroom under the cap. See `docs/roadmap/recursion.md` § R4.8.

**Recursion gadget set complete (R3.6) + audit** (2026-06-17). The Poseidon2 ladder t=2/t=4/t=8 is complete (`QLSAVerifierVFRI11`, t=8 → ~2^62 node collision). ~~full-V23 t=8 on-chain `verify()` exceeds 100M gas at depth-10; decision: skip the standalone t=16 verifier (VFRI12)~~ — **both claims were later refuted by measurement** (R4.8: the 100M was Poseidon2 implementation overhead, real cost 3.34M; R4.22: VFRI12 verifies a full V23 batch at 15.44M in one transaction). The direction below was still right, for a different reason — recursion is what makes production 130-bit FRI soundness reachable at all. **Went straight to proof recursion** — a STARK proving "I verified a VFRI11 STARK" gives constant ~5M on-chain gas with any inner hash width. The **full recursion AIR gadget set** is now built (R0.1–R3.6, **88 tests**): QM31 arithmetic, FRI circle/line fold, OODS quotient, Poseidon2 Merkle auth-path, Fiat-Shamir absorb **+ draw**, per-query composition (single + N-query aggregation), and the leaf-hash → Merkle integration.

**Recursion audit (2026-06-17) — C1/C2 closed for `recursive_verifier`:** a two-expert audit (crypto + code) found two composition-level soundness gaps; **both are now fixed for the flagship composition gadget** (single + N-query): **[C1]** the verifier-fixed claimed final is carried in pinned `fin0..fin3` preprocessed columns with an `is_output`-gated in-circuit constraint tying the trace's real output to it (a prover computing X can't claim Y≠X); **[C2, was reproduced]** selectors + output columns come from one canonical source (`build_preproc`) and the verifier recomputes + pins their commitment root (`canonical_preproc_root`), so a forged `is_step≡0` no longer verifies (previously it verified `true`). Two regression tests (`test_forged_selector_rejected`, `test_forged_output_cannot_prove`). **Remaining R3.7 follow-up:** port the same pinning to the standalone sub-gadgets and the mature V23/VFRI verifiers (same unpinned pattern — codebase-wide review item; `recursive_verifier` is the reference). Robustness fixes applied: input caps, empty-input guard, `bits_to_index` depth assert. See `docs/roadmap/recursion.md` § R3.7. 437 Rust (+90 recursive) + Solidity (+24 t=8 backend) tests green.

| Component | Status |
|-----------|--------|
| `core/` — ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| `stark_stwo/src/mldsa/` — Pure Rust ML-DSA-65 verifier (FIPS 204) | ✅ Done |
| `stark_stwo/` — Stwo Circle STARK prover (Rust), 130-bit FRI security | ✅ Done |
| ML-DSA arithmetic AIR circuits (8 components → 1 STARK, **V23**) | ✅ Done |
| `stark/` — Python prover/verifier wrappers V4–V23 + VFRI7/VFRI8/VFRI9 hint generators | ✅ Done |
| `contracts/` — BatchRegistry(V2–**V5**), QLSAVerifier(V4–**VFRI9**), Poseidon2Channel/Merkle/MerkleW | ✅ Done |
| `aggregator/` — Mempool, Batcher, AggregatorNode, rate limiting, HTTP API, prover-crash recovery | ✅ Done |
| Tests — **323 Rust** + **354 Python** (no PyO3) / **~560** (with PyO3) + **~71 TS** + **958 Hardhat** | ✅ Done |
| `sdk/` — Python SDK (Wallet, LocalClient, HttpClient, WitnessStatus + VFRI9 fields) + JS SDK (VFRI9 parity) | ✅ Done |
| Phase 6 — Sepolia testnet: first batch finalized (4 tx, 3234-byte proof, 9.16 s) | ✅ Done |
| **V23** — 8-component STARK, RangeQBatch, az_hat ∈ [0,Q) — closes AzFull soundness gap | ✅ Done |
| **QLSAVerifierVFRI7** — VFRI6 + `mixRoot(merkleRoot)` + cross-proof binding | ✅ Done (2026-05-25) |
| **BatchRegistryV4** — Dual-VFRI7: `boundRoot = keccak256(batchRoot ‖ traceRootOther)` | ✅ Done (2026-05-25) |
| **QLSAVerifierVFRI8** — VFRI7 + Poseidon2 Merkle + Poseidon2Channel; ≤ 15M gas for 20 queries | ✅ Done (2026-06-10) |
| **BatchRegistryV5** — Dual-VFRI8/VFRI9 registry; proof length guards; cross-proof binding identical to V4 | ✅ Done (2026-06-10) |
| **Full V23 dual-VFRI8 E2E** — Both trace groups (3504 cols) verified on-chain via fixture | ✅ Done (2026-06-10) |
| **Security + code audit (2026-06-10)** — 21 findings, 18 fixed: dead code removal, proof length guards, rate limiting `/stats`/`/node/config`, `_sender_txs` memory leak, VFRI8 `witness_commitment` fallback, `_verifyOODS` no-mutation refactor, `num_folds_log8` silent-drop fix | ✅ Done (2026-06-10) |
| **QLSAVerifierVFRI9** — last-layer FRI check + wide Poseidon2 nodes + full-root Fiat-Shamir; closes the VFRI5–8 bounded-degree soundness gap | ✅ Done (2026-06-10) |
| **Aggregator liveness** — prover-crash recovery (txs returned to mempool, ≤3 retries), `prepend_batch` overflow accounting, config validation | ✅ Done (2026-06-10) |
| **API auth** — Bearer token (`QLSA_API_TOKEN`) on `/batch/run` + `/batch/flush`, constant-time compare | ✅ Done (2026-06-10) |
| **VFRI9 aggregator pipeline** — `BatchResult.has_vfri9` + vfri9 proof/commitment fields; API + Python SDK + JS SDK expose VFRI9 commitments | ✅ Done (2026-06-12) |
| **pyo3 0.24→0.29** — fixes RUSTSEC-2026-0176 (OOB read in `PyList`/`PyTuple` iterators) and RUSTSEC-2026-0177 (`PyCFunction` missing `Sync`); no source changes | ✅ Done (2026-06-12) |
| **JS SDK VFRI9 parity** — `WitnessStatus`/`BatchStatus` gain `hasVfri9` fields; `RawBatchStatus` interface deduplicates 5 inline copies of API wire shape | ✅ Done (2026-06-12) |
| **Poseidon2 t=4 (MVP-6 groundwork)** — `poseidon2_t4.rs` + `Poseidon2M31T4.sol`: R_F=8, R_P=21, rate-2 cap-2 sponge; 124-bit compress (collision ~2^62); 315 Rust / 917 Solidity tests | ✅ Done (2026-06-12) |
| **VFRI10 + t=4 hash backend** — `QLSAVerifierVFRI10` (VFRI9 protocol, t=4 Merkle + channel) + V23 cross-bound Rust/PyO3/Python pipeline + dual-group E2E via `BatchRegistryV5` | ✅ Done (2026-06-14) |
| **Security + code audit** — off-chain replay guard (`ReplayedTxError`), submit error-text hardening, `/stats` overflow metric, release-build test-fixture gating, FRI `tree_depth` guard | ✅ Done (2026-06-14) |
| **BatchRegistryV6** — per-group split: each V23 t=4 group `verify()` in its own tx (now 2.15M / 1.70M gas); finalizes the full batch across two txs with cross-proof binding preserved. Since R4.8 the split is optional — single-tx `BatchRegistryV5` fits both groups | ✅ Done (2026-06-14) |
| **MVP-6 testnet tooling** — `deploy_v6.js`/`deploy_v6.sh` (VFRI10 + BatchRegistryV6), `OnchainSubmitterV6` per-group split flow, `e2e.py --stack v6` (`num_folds=6`); MVP-5 V4 path kept for regression | ✅ Done (2026-06-16) |
| **MVP-7 testnet tooling (t=8 stack, now the DEFAULT)** — `deploy_v7.js`/`deploy_v7.sh` (VFRI11 + BatchRegistryV5), `OnchainSubmitterV5` single atomic `submitBatchWithNonces`, `e2e.py --stack v7` (default). Node collision ~2^62 (vs t=4's ~2^31) in ONE transaction at ~6.06M gas; registry-shape guard rejects a `REGISTRY_ADDRESS` that does not match the chosen stack | ✅ Done (2026-07-30) |
| **VFRI10 in the aggregator** — `Batcher` now emits VFRI10 witness proofs (`num_folds=6`), surfaced through `BatchResult.has_vfri10`, the API witness endpoints, and the Python + JS SDKs | ✅ Done (2026-06-16) |
| **Poseidon2 t=8 (128-bit ladder groundwork)** — `poseidon2_t8.rs` + `Poseidon2M31T8.sol` cross-checked bit-exact: R_F=8, R_P=14, block external matrix, 4-word (124-bit) nodes → ~2^62 collision (vs t=4's 2^31). Next rung toward t=16 ≈ 128-bit (Stwo's native Poseidon2-16). 11 JS + 12 Rust tests | ✅ Done (2026-06-16) |
| **Poseidon2 t=8 hash backend** — `Poseidon2MerkleVerifierT8` (4-word/124-bit nodes) + `Poseidon2ChannelT8` (217-bit capacity Fiat-Shamir) + Rust `hash_*_p2t8` / `P2T8Channel`, cross-checked bit-exact (13 JS + 6 Rust). Ready for a VFRI11 verifier | ✅ Done (2026-06-16) |
| **QLSAVerifierVFRI11** — VFRI10 protocol on the t=8 backend (4-word nodes → ~2^62 node/transcript collision); identical ABI, version marker 5. On-chain `verify()==true` at ~13.1M gas (generic depth-4 fixture). 3 Rust + 11 JS E2E tests | ✅ Done (2026-06-16) |
| **VFRI11 V23 pipeline** — cross-bound Rust/PyO3/Python wrappers (`prove_mldsa_sig_vfri11_stark`) + 7 Python + 11 JS E2E (BatchRegistryV5 wired to VFRI11). Both t=8 groups verify on-chain (LOG=10 3.34M / LOG=8 2.63M gas) and finalize in ONE `submitBatch` at 6.06M — the earlier ">100M gas" figure was Poseidon2 implementation overhead, removed in R4.8 | ✅ Done (2026-06-16, gas 2026-07-30) |
| **Path decision: skip standalone t=16, go to recursion** — a standalone t=16 verifier hits the same gas wall ~4× worse; t=16 (128-bit) instead becomes the recursion's inner hash AIR (constant on-chain cost). `docs/roadmap/recursion.md` | ✅ Decided (2026-06-17) |
| **Recursion R0.1 — QM31-mul AIR** — `recursive/qm31_mul_air.rs`: proves `z = x·y` in QM31 = CM31[u]/(u²−R); 4 degree-2 constraints, full prove/verify roundtrip + hand-verified soundness. Load-bearing primitive for circleFold/lineFold/OODS. 8 Rust tests | ✅ Done (2026-06-17) |
| **Security + code audit (VFRI11/t=8/recursion)** — 2 experts, no Critical/High/Medium; fixed `deploy_v6.sh --network` flag, CLI arg validation, web3 timeouts, `.env.deployed` 0600, t=8 sponge `% P` parity, QM31 limb-canonicity precondition | ✅ Done (2026-06-17) |
| **Recursion R1 — FRI fold + OODS AIRs** — `fold_air.rs`: proves `folded=(f₊+f₋)+α·(f₊−f₋)·inv` (21 cols, helper column lowers to degree-2); `oods_air.rs`: proves `fₚ·(px−z_x)=compValue−oodsCombo` (17 cols, multiplicative form — avoids QM31 inverse). 8+8 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R2 — Merkle path + Fiat-Shamir AIRs** — `merkle_path_air.rs`: proves `leaf@index+siblings→root` via Poseidon2 t=2 compression (10 main + 4 preproc cols, index-bit child selection, cross-row cur chaining); `channel_air.rs`: proves Poseidon2 duplex sponge absorption — `mixU32s` core (7 main + 4 preproc cols). 10+9 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.1 — per-query FRI step AIR** — `query_step_air.rs`: first composition gadget; chains OODS± + circle fold in one row per query (42 cols, 16 degree-2 constraints). `step_ref()` cross-checks against `oods_air` + `fold_air` references. 7 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.2 — FRI fold chain AIR** — `fri_fold_chain_air.rs`: K line-fold rounds chained via cross-row constraint `input[k]=output[k−1]` (21 main + 1 preproc). 9 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.3 — per-query recursive verifier** — `recursive_verifier.rs`: OODS± + circle fold + K line folds in ONE AIR; data flow enforced by cross-row constraint (42 main + 2 preproc selectors). 9 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.4 — per-query integration** — `integration.rs`: `recursive_verifier → qm31_leaf_hash → merkle_path_air`, full per-query FRI verification value-bound across 3 sub-proofs. 3 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.5 — multi-query aggregation** — `prove_recursive_queries`: N queries in ONE STARK (N blocks of 1+K rows, same AIR, all finalFolds bound). 5 Rust tests | ✅ Done (2026-06-17) |
| **Recursion R3.6 — Fiat-Shamir draw AIR** — `transcript_draw_air.rs`: Poseidon2 t=2 squeeze chain (`drawSecureFelt`/`drawQueries` core), dual of `channel_air` absorb. 11 Rust tests. **Full recursion gadget set complete: 88 tests** | ✅ Done (2026-06-17) |
| **Recursion audit — C1/C2 closed for `recursive_verifier`** — [C1] `is_output`-gated in-circuit constraint pins trace output to verifier-fixed claimed final (pinned `fin` preproc cols); [C2] `canonical_preproc_root` recomputes + pins the preprocessed commitment (forged `is_step` no longer verifies). 2 regression tests. Robustness fixes (caps, guards, asserts) | ✅ Done (2026-06-17) |
| **C2 pinning — codebase-wide (every preprocessed verifier)** — 4 recursion sub-gadgets + `recursive_verifier` + 5 production `is_init_uh` verifiers (incl. **V23**, `canonical_uh_preproc_root`) + Poseidon2 hash-chain (`canonical_hashchain_preproc_root`). No verifier accepts an unpinned Tree 0. Forged `is_init_uh` (could bypass OMEGA bound) rejected; honest V21/V22/V23 + hash-chain roundtrips pass. 443 fast Rust tests green | ✅ Done (2026-06-17) |
| **Recursion composition — multi-gadget recursive proof (single + N-query)** — `recursive/composition.rs`: `recursive_verifier` + `merkle_path` in ONE multi-component STARK. `prove_query_membership` (1 query) and `prove_queries_membership` (**N queries + N Merkle paths — the VFRI11 shape**, via multi-path merkle). Each `finalFold → hashLeaf → Merkle root` bound end-to-end; merkle `leaf` bound in-circuit (C1). 101 recursive tests | ✅ Done (2026-06-17) |
| **Recursion — FRI cherry-pick fully closed (1a)** — key design realization: the cheap Poseidon2 channel stays on-chain, so challenges are public inputs to the recursive proof → **no logup needed**. `recursive_verifier` pins ALL verifier-fixed challenge inputs in-circuit (`alpha` fold challenge, `z_x` OODS point, `px` query point, `inv` twiddle — 17 preproc columns); a prover can't cherry-pick any of them. 103 recursive tests | ✅ Done (2026-06-17) |
| **Recursion audit R3.12 — Merkle root binding (C1) closed** — the claimed `root` is pinned in-circuit in `merkle_path_air` (`is_root`-gated `s0 − root_pinned = 0`); previously only Fiat-Shamir-mixed, so a fresh dishonest proof for a false root claim verified. `depth` is now an explicit public input. Composition value-bound end-to-end in-circuit. + input caps (MAX_QUERIES/MAX_NUM_FOLDS/MAX_DEPTH/log_size/capacity) close panic/OOM paths on hostile inputs. 104 recursive tests | ✅ Done (2026-07-10) |
| **Recursion R3.13 — wide inner-hash primitive (t=8 compression AIR)** — `recursive/poseidon2_t8_air.rs` arithmetizes `compress_t8` (4-word/124-bit nodes → ~2^62 node collision), the hash a VFRI11 inner proof uses. 40 main + 11 preproc cols, one round/row, exact mat_external/mat_internal, C2-pinned; validated against the cross-checked `permute_t8` reference. 111 recursive tests | ✅ Done (2026-07-13) |
| **Recursion R3.14 — wide Merkle-path AIR (t=8, 124-bit nodes)** — `recursive/merkle_path_t8_air.rs` authenticates a path over 4-word nodes via `compress_t8` (node collision 2^15.5 → 2^62), the path a VFRI11 FRI-layer decommitment uses. 45 main + 22 preproc cols; C1 index/leaf/root binding in-circuit (matches on-chain `Poseidon2MerkleVerifierT8.verify`) + C2 pinning; reuses R3.13's round arithmetization across depth compressions via the `out[-1]` adjacency chain. 122 recursive tests | ✅ Done (2026-07-13) |
| **Recursion R3.15 — wide (t=8) composition** — `recursive/composition_t8.rs` proves `recursive_verifier` + `merkle_path_t8` in ONE STARK (the t=8 analogue of `composition`), lifting the recursion's inner-hash node collision to ~2^62. Binds `leaf4 = qm31_leaf_hash_t8(finalFold)` into the wide path: value-bound end-to-end in-circuit (finalFold → hashLeaf_t8 → leaf → t=8 path → root). 125 recursive tests | ✅ Done (2026-07-13) |
| **Recursion R3.16 — N-query wide composition (VFRI11 shape on t=8)** — `prove_queries_membership_t8` proves N fold chains + N wide (4-word-node) Merkle paths in ONE STARK via new multi-path t=8 builders (AIR unchanged). Per-query leaves recomputed + pinned, every path root pinned in-circuit, input caps from the start. 127 recursive tests | ✅ Done (2026-07-16) |
| **Recursion R3.17 — the 128-bit inner hash (t=16 permutation + compression AIR)** — `poseidon2_t16.rs`: Poseidon2 t=16 (R_F=8/R_P=14, documented RC derivation, invertible M_I) with 2-to-1 compression over 8-word (248-bit) nodes → **~2^124 ≈ 128-bit node collision**, the final ladder rung (Stwo native width). `poseidon2_t16_air.rs` arithmetizes `compress_t16` (80+19 cols, C2-pinned, expr layers cross-checked). 134 recursive tests | ✅ Done (2026-07-16) |
| **Recursion R3.18 — 128-bit inner-hash stack COMPLETE (t=16 path AIR + composition)** — `merkle_path_t16_air` (8-word/248-bit nodes) + `composition_t16` (single + N-query VFRI11 shape): finalFold → hashLeaf_t16 → leaf8 → t=16 path → root, all pinned in-circuit at **~2^124 ≈ 128-bit node collision**. The t=2→t=8→t=16 ladder is complete; each rung a pure hash-backend swap. 150 recursive tests | ✅ Done (2026-07-16) |
| **Recursion R4.1 — verifies the REAL VFRI11 pipeline (root vs committed FRI-layer root)** — shared `vfri11_fri_chain` (ABI generator + bridge can't drift) + `gen_vfri11_recursion_inputs`: per-query StepOp/fold-rounds (index-oriented twiddle inverses) + final-fold path into the COMMITTED last-layer tree, hard extraction invariant. E2E: recursive proof over real data verifies; tampered root rejected. Next: on-chain channel-replay + `QLSAVerifierRecursive.sol`. 507 tests | ✅ Done (2026-07-16) |
| **Recursion R4.2–R4.7 + audit — on-chain half of the recursion** — Rust channel-replay reference → `RecursiveChannelReplay.sol` (byte-identical, CI-verified) → `QLSAVerifierRecursive.sol`. Audit fixed a HIGH: the cross-binding covered only 2 of 8 public inner fields, so an outer proof could be reused with the others swapped; it now hashes every field. ~~Measured limit: the full outer verification exceeds a 29M-gas call~~ — refuted in R4.8; the honest path had never executed (a gasLimit above 2^24 is rejected before execution) and the cost was implementation overhead. Real: `verifyRecursive` 2.29M, full v8 batch 13.17M in one transaction. 516 Rust tests, 1011 Solidity | ✅ Done (2026-07-26) |
| **Audit R3.13–R4.1 — C1 input/output binding closed in compression AIRs** — crypto+code audit of the t=8/t=16 stack + VFRI11 bridge. HIGH fix: `poseidon2_t{8,16}_air` `prove/verify_compress` bound `(left,right,node)` only via Fiat-Shamir (a false `compress(FAKE)=node` claim could verify — latent, test-only, not production); now pinned in-circuit (`raw_pin`/`node_pin` + gated equality, regressions `test_forged_input_cannot_prove`). + t=16 matrix naive cross-checks (M_E/M_I verified) + stale-doc/capacity fixes. Clean elsewhere. 513 tests | ✅ Done (2026-07-16) |

---

## Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`

### Layer 2 — Aggregation (off-chain)

- Collect transactions (mempool → batcher)
- Verify ML-DSA-65 signatures (pure Rust FIPS 204 verifier, off-circuit)
- Build Merkle tree with SHA3-512 → `merkle_root`
- Generate Stwo Circle STARK proof (V23) — all 8 arithmetic circuits in **1 FRI commitment**
  - Fiat-Shamir transcript binds both `c_tilde` (ML-DSA challenge) and `merkle_root` (batch)
  - RangeQBatch proves az_hat[j][p] ∈ [0, Q) — closes the AzFull multiplication soundness gap
- `onchain_commitment` = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]

### Layer 3 — Verification (on-chain)

- **BatchRegistryV5** (dual-VFRI9): two independent VFRI9 `verify()` calls — LOG=10 and LOG=8 groups
- Cross-proof binding: `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)`, `boundRoot8 = keccak256(batchRoot ‖ traceRoot10)` — FRI query indices depend on the other group's trace commitment
- Last-layer FRI check: prover supplies all `2^(treeDepth−K)` final-layer evaluations; verifier rebuilds the Merkle tree with wide Poseidon2 nodes (62-bit) and asserts root == `friLayerRoots[K]`
- Full-root Fiat-Shamir: `mixRootFull` absorbs all 32 bytes of trace root and batch Merkle root
- Each VFRI9 call runs ≤ 15M gas regardless of column count (O(1) in n_cols)
- Combined calldata: ~12.5 KB (7.2 KB LOG=10 + 5.3 KB LOG=8)
- Store `merkle_root` + both commitments on-chain (nonce-ordered replay protection)

---

## Tech Stack

### Cryptographic Core

- **ML-DSA-65** — FIPS 204 (liboqs-python 0.14.1 + pure Rust verifier)
- **SHA3-512** — Merkle hashing
- **SHA3-256** — address scheme
- **Blake2s-256** — proof commitment binding

### STARK Layer

| Stage | Stack | Status |
|-------|-------|--------|
| Active | Stwo 2.2.0 (Circle STARK, Rust nightly-2025-07-01) | Active |
| Legacy | Winterfell v0.13.1 | Archived |

**ML-DSA arithmetic circuits (V23 — all 8 in one STARK proof, current production):**

| Circuit | LOG | Columns | Proves |
|---------|----:|--------:|--------|
| NttBatch | 10 | 649 | NTT(z, c, t1) → z_hat, c_hat, t1_hat |
| AzFull | 8 | 1523 | A·z matrix-vector product (NTT domain) |
| Ct1Full | 8 | 295 | c·t1 polynomial product (NTT domain) |
| InttBatch | 10 | 649 | INTT(az_hat, ct1_hat) → az_out, ct1_out |
| WPrimeFull | 8 | 24 | w′ = az_out − ct1_out |
| NormCheckBatch | 8 | 15 | ‖z‖∞ ≤ γ₁ − β per coefficient |
| UseHintBatchV2 | 8 | 61+1 | UseHint(w′, hints) → w1_prime |
| **RangeQBatch** ← NEW | 8 | **288** | **az_hat[j][p] ∈ [0, Q) — closes AzFull soundness gap** |
| **Total** | | **3505** | **Full ML-DSA.Verify arithmetic witness + range check** |

**Sub-proof reduction history:**

| Version | Sub-proofs | Key change |
|---------|:----------:|-----------|
| V17 | 5 | NormCheck+UseHint merged |
| V18 | 4 | INTT+WPrime merged |
| V19 | 3 | NTT+Az+Ct1 merged |
| V20 | 2 | INTT+WPrime+Norm+UseHint merged |
| **V21** | **1** | **All 7 components — single FRI commitment** |
| **V22** | **1** | **+ Merkle root Fiat-Shamir binding** |
| **V23** | **1** | **+ RangeQBatch (az_hat ∈ [0,Q)) — closes soundness gap** |

### Infrastructure

- Python 3.10+
- `liboqs-python==0.14.1`
- Solidity + Hardhat (OpenZeppelin v5)
- Deployed on Ethereum Sepolia testnet

---

## Security Notes

| Issue | Severity | Status |
|-------|----------|--------|
| On-chain FRI verifier — full multi-round FRI with OODS | Critical | ✅ Done (VFRI2/VFRI3, 2026-05-19) |
| FRI soundness — `N_FRI_QUERIES=3` default (22-bit) | High | ✅ Fixed (LOG_BLOWUP=6, 20 queries, POW_BITS=10 → 130-bit, 2026-05-19) |
| ML-DSA verification inside AIR circuit | Critical | ✅ Done (V21: 1 STARK proof, 2026-05-16) |
| Merkle root not a public input of the STARK proof | Critical | ✅ Done (V22: Fiat-Shamir binding, 2026-05-16) |
| AzFull multiplication soundness gap (az_hat not range-checked) | High | ✅ Closed (V23: RangeQBatch 288 cols, 2026-05-20) |
| M31 wrap-around soundness gap in multiplication | High | ✅ Closed (Q-range check AIR, 2026-05-14) |
| c_tilde not bound to STARK proof | High | ✅ Done (Fiat-Shamir mixing, 2026-05-14) |
| No replay protection on-chain | High | ✅ Done (`submitBatchWithNonces()`, BatchRegistryV2) |
| On-chain OODS O(n_cols) gas bottleneck | High | ✅ Done (VFRI6: off-chain combo, O(1) gas, 2026-05-22) |
| `submitBatchWithNonces` O(n²) dedup — no sender count cap | Medium | ✅ Fixed (`MAX_SENDERS = 3000` in V2/V3/V4, 2026-05-22) |
| `_history` list unbounded growth (memory leak) | Medium | ✅ Fixed (capped at 1000 entries with eviction, 2026-05-22) |
| Circle fold y=0 — M31.inv panic on identity point | Low | ✅ Fixed (explicit y==0 guard in VFRI4/5/6, 2026-05-22) |
| `stark_stwo/target/` not in .gitignore | Low | ✅ Fixed (.gitignore updated, 2026-05-22) |
| Non-constant-time Merkle root comparison | Medium | ✅ Fixed (`hmac.compare_digest`, 2026-05-20) |
| X-Forwarded-For spoofing in rate limiter | Medium | ✅ Fixed (take rightmost IP, 2026-05-20) |
| Rate limiter eviction thread-safety (KeyError race) | Medium | ✅ Fixed (`dict.pop` + evict both windows, 2026-05-20) |
| Missing k/l bounds check in combined STARK | Medium | ✅ Fixed (`_validate_mldsa65_inputs`, 2026-05-20) |
| Solidity MerkleVerifier uncapped depth (overflow at depth≥256) | Medium | ✅ Fixed (`depth > 32` guard, 2026-05-20) |
| CM31.fromBytes8LE no M31 range check | Medium | ✅ Fixed (`require(a < P && b < P)`, 2026-05-20) |
| treeDepth upper bound missing in V11/V12/V13 | Low | ✅ Fixed (`> 30` guard added, 2026-05-20) |
| API rate limiting | Medium | ✅ Done (100 tx/min, 20 batch ops/min per IP) |
| On-chain n_queries=1 → 16-bit soundness (gas constraint) | High | Open (gas optimisation deferred to MVP-4; n configurable via `N_FRI_QUERIES` env var) |
| Private key zeroing in Python is best-effort | Medium | Open (Rust `wipe_bytes` via `zeroize`; Python-side copy unavoidable) |
| Hash AIR `H(a,b) = a³+b` not cryptographic | Low | ✅ Done (Poseidon2-over-M31, 2026-05-16) |
| Non-constant last FRI layer (bounded-degree check) | High | ✅ Done (QLSAVerifierVFRI3, 2026-05-19) |
| No cross-proof binding between LOG=10 and LOG=8 groups | Medium | ✅ Done (VFRI7: `mixRoot(merkleRoot)` before `drawQueries`; BatchRegistryV4 cross-bound roots, 2026-05-25) |
| `deserialize_public_key` accepted any-size bytes | Medium | ✅ Fixed (ML-DSA key size validation, 2026-05-25) |
| Dead code in `gen_mldsa_v23_vfri7_cross_bound_hints` (`pass` block) | Low | ✅ Fixed (raises `ValueError` when folds differ, 2026-05-25) |
| Silent sender truncation in `submit.py` | Medium | ✅ Fixed (`_validate_senders` raises on wrong-size input, 2026-05-25) |
| `TwoChannel.drawQueries` uint256 overflow (`logDomainSize >= 256`) | Low | ✅ Fixed (`require(logDomainSize <= 31)` guard, 2026-05-25) |
| `TRUSTED_PROXIES` hardcoded — operators could not add their own reverse proxy without code change | Medium | ✅ Fixed (configurable via `TRUSTED_PROXIES` env var, 2026-05-30) |
| `Transaction.amount = 0` accepted by SDK but rejected by API — silent mismatch | Medium | ✅ Fixed (`amount ≥ 1` enforced in `__post_init__`, 2026-05-30) |
| `Mempool.prepend_batch()` silently dropped transactions when full | Medium | ✅ Fixed (`logging.warning` on drop, 2026-05-30) |
| `Batch.stark_commitment_onchain()` dead code — always raised `ValueError` with real commitments | Bug | ✅ Fixed (method removed, 2026-05-30) |
| `wait_and_verify` caught all `Exception` — masked real network errors | Medium | ✅ Fixed (only "not found" suppressed, 2026-05-30) |
| No `GET /batch/{id}` endpoint — clients could not query batch status without re-proving | Low | ✅ Fixed (endpoint added to HTTP API, 2026-05-30) |
| `WitnessStatus.fri_security_bits` missing from Python SDK | Low | ✅ Fixed (field added: `6 × n_fri_queries + 10`, 2026-05-30) |
| `fastapi`/`httpx` duplicated in both `requirements-api.txt` and `requirements-dev.txt` | Low | ✅ Fixed (`-r requirements-api.txt` reference, 2026-05-30) |
| `TRUSTED_PROXIES` env value not IP-validated — malformed token added to whitelist | Medium | ✅ Fixed (`ipaddress.ip_address()` + warning+skip, 2026-05-30) |
| `public_key`/`signature` not normalized to lowercase in API validators | Low | ✅ Fixed (`.lower()` added, matching sender/recipient, 2026-05-30) |
| GET `/batch/*` endpoints unrate-limited — O(n) history scan DoS vector | Medium | ✅ Fixed (200 req/min per IP, 2026-05-30) |
| `batch_id` accepted any string — no UUID format validation | Low | ✅ Fixed (`uuid.UUID()` guard, HTTP 400 on bad format, 2026-05-30) |
| `Transaction.public_key` not size-validated in `__post_init__` | Medium | ✅ Fixed (validates against ML-DSA sizes {1312, 1952, 2592} B, 2026-05-30) |
| `create_batch()` algorithm not validated before first `verify()` call | Low | ✅ Fixed (early check at function entry, 2026-05-30) |
| `node._history` list slice eviction — new list allocated every eviction cycle | Medium | ✅ Fixed (`deque(maxlen=1000)` + O(1) `_batch_index` dict, 2026-05-30) |
| `N_FRI_QUERIES` env var unchecked — crash on non-integer value at startup | Medium | ✅ Fixed (`try/except ValueError` + range `[1, 64]` check, 2026-05-30) |
| `batcher.py` used root logger — module-level filtering impossible | Low | ✅ Fixed (`logging.getLogger(__name__)`, 2026-05-30) |
| `HttpClient.submit()` missing `KeyError` guard on response parsing | Low | ✅ Fixed (`try/except KeyError` matching pattern of `run_cycle`/`flush`, 2026-05-30) |
| No `GET /node/config` endpoint — clients had to hard-code n_fri_queries / batch size limits | Low | ✅ Fixed (endpoint + `NodeConfig` model in Python SDK, TypeScript SDK, 2026-06-03) |
| `HttpClient.run_cycle/flush` ignored `prove_witnesses` param — always sent without flag | Low | ✅ Fixed (`?prove_witnesses=true` query param forwarded; same fix in TypeScript SDK, 2026-06-03) |
| `Dockerfile` had no env var documentation — operators unaware of `N_FRI_QUERIES`/`TRUSTED_PROXIES` | Low | ✅ Fixed (documented `ENV` defaults with security trade-off comments; `docker-compose.yml` pass-through, 2026-06-03) |
| `HttpClient` all JSON call-sites — unhandled `json.JSONDecodeError` when proxy returns HTML body with 2xx status | Medium | ✅ Fixed (`_decode_json()` static method wraps `resp.json()`, raises `RuntimeError` with 200-char preview, 2026-06-03) |
| `testnet/e2e.py` redundant SHA3-256 recomputation — `sender_key` re-derived via `hashlib` though already in `tx.sender` | Low | ✅ Fixed (`bytes.fromhex(tx.sender)`, removed `import hashlib`, 2026-06-03) |
| `aggregator/__main__.py` bandit B104 — `"0.0.0.0"` default flagged as hardcoded bind-all | Info | ✅ Fixed (`# nosec B104` — intentional, address is `--host`/`HOST` configurable, 2026-06-06) |
| Off-chain replay — an already-batched tx could be re-submitted and re-batched (mempool dedup covers only pending txs) | High | ✅ Fixed (`ReplayedTxError` guard in `AggregatorNode.submit()` rejects re-submission of any tx still in retained batch history; on-chain nonce registry is the durable backstop, 2026-06-14) |
| `POST /transactions` echoed raw `str(exc)` — leaked internal validation/capacity detail | Low | ✅ Fixed (fixed client messages `invalid transaction`/`mempool full`; detail logged server-side, 2026-06-14) |
| Test fixtures compiled into the release library (`mod tests` lacked `#[cfg(test)]` in `vfri2_bridge.rs`) | Low | ✅ Fixed (gated; release build warning-free, 2026-06-14) |
| Generic FRI generators validated only `tree_depth ≥ 2` — `coset_at` shift underflow for depth > 30 | Low | ✅ Fixed (`tree_depth ∈ 2..=30` guard, mirrors on-chain `logDomainSize > 30`; not attacker-reachable, 2026-06-14) |

For the full cryptography and security analysis, see `context.md`.

---

## Performance

| Metric | Value |
|--------|-------|
| Batch size | up to 3,000 tx |
| Proof size (hash chain STARK) | ~90–200 KB |
| On-chain verification | O(1) |
| Sepolia first batch (4 tx) | 3,234-byte proof, 9.16 s |
| V23 STARK columns | 3,504 main + 1 preproc (8 components, 1 FRI commitment) |
| VFRI7 LOG=10 gas (1298 cols, 1 query) | ≤ 15M gas |
| VFRI7 LOG=8 gas (2206 cols, 1 query) | ≤ 15M gas |
| Dual-VFRI7 combined calldata | ~12.5 KB |
| V23 slow test (full witness) | ~95 s (optimized build, `#[ignore]`) |

Benchmarks: `/benchmarks/bench_core.py`, `bench_stark.py`, `bench_poly_circuits.py`, `bench_witnesses.py`.

---

## Repository Structure

```text
QLSA/
├── core/               # ML-DSA keys, signing, Merkle tree, batch
├── stark/              # Python prover/verifier wrappers V4–V23, witness pipeline
├── stark_stwo/         # Stwo Circle STARK prover (Rust), ML-DSA arithmetic circuits
├── aggregator/         # Mempool, Batcher, AggregatorNode, HTTP API
├── contracts/          # Solidity: BatchRegistry(V2/V3/V4), QLSAVerifier(V4–V13/VFRI–VFRI7), CM31/QM31/MerkleVerifier
├── sdk/python/         # Python SDK: Wallet, LocalClient, HttpClient, WitnessStatus
├── sdk/js/             # TypeScript SDK: AggregatorClient
├── benchmarks/         # bench_core, bench_stark, bench_poly_circuits, bench_witnesses
├── testnet/            # e2e.py (--stack v7/v6/v4), deploy.sh, deploy_v6.sh, deploy_v7.sh, submit.py, monitor.py
├── tests/              # ~350 Python tests (no PyO3) + ~552 with PyO3 ext (pytest)
├── context.md          # Technical decisions, architecture log, security risk table
└── README.md
```

---

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| Phase 2 | Stwo Circle STARK prover (hash chain AIR) | ✅ Done |
| Phase 3 | Solidity contracts (BatchRegistry + verifier) | ✅ Done |
| Phase 3+ | M31 library + QLSAVerifierV2 + FRI blowup | ✅ Done |
| Phase 3++ | Blake2s.sol + QLSAVerifierV3 + QLSAVerifierFull | ✅ Done |
| MVP-4 (partial) | CM31/QM31 field libs + MerkleVerifier + QLSAVerifierV4–V13 | ✅ Done |
| Phase 4 | Aggregator: Mempool, Batcher, AggregatorNode | ✅ Done |
| Phase 5 | SDK: Python + JavaScript + HTTP API | ✅ Done |
| MVP-3 | ML-DSA batch verifier (Rust FIPS 204) + STARK bridge | ✅ Done |
| **Phase 6** | **Testnet deployment — Sepolia, first batch 2026-05-05** | ✅ Done |
| **MVP-3+** | **All 7 ML-DSA circuits → 1 STARK proof (V21) + Merkle root binding (V22)** | ✅ Done |
| **QLSAVerifierVFRI2** | **K-round parametric FRI + constant last-layer check (full on-chain FRI protocol)** | ✅ Done |
| **Security fix** | **LOG_BLOWUP=6, N_FRI_QUERIES=20, POW_BITS=10 → 130-bit FRI soundness** | ✅ Done |
| **QLSAVerifierVFRI3** | **Non-constant last-layer polynomial bounded-degree check (MVP-4 complete)** | ✅ Done |
| **VFRI3 bridges** | **Generic `gen_vfri3_hints_from_cols` + Poseidon2 + ML-DSA NttBatch VFRI3 bridges; E2E contract stack** | ✅ Done |
| **V23** | **RangeQBatch 8th component — az_hat ∈ [0,Q) range check closes AzFull soundness gap** | ✅ Done |
| **Security audit** | **Constant-time Merkle verify, rate-limit thread safety, input validation, Solidity depth guards** | ✅ Done |
| **MVP-5** | **Cross-proof binding VFRI7 + aggregator/SDK VFRI7 wiring + security audit** | ✅ Done (2026-05-25) |
| MVP-4 final | RPO256 hash AIR + Yul-optimised Blake2s + full V23 OODS wiring (20 queries, blowup 64) | ⏳ Next |

---

## Risks & Mitigations

### 1. ML-DSA inside STARK (main research challenge)

**Status: Solved (V21/V22).**

All 8 ML-DSA.Verify arithmetic components (NTT, Az, Ct1, INTT, WPrime, NormCheck, UseHint, **RangeQBatch**) now run inside a single Circle STARK FRI proof (3,505 trace columns). The proof is cryptographically bound to both the ML-DSA challenge (`c_tilde`) and the batch Merkle root via Fiat-Shamir transcript mixing. The new RangeQBatch component closes the primary soundness gap: AzFull's 23-bit decomposition of multiplications is now completed by an explicit proof that all K=6 output coefficients az_hat[j][p] lie in [0, Q).

**On-chain FRI (QLSAVerifierVFRI2):** completes the FRI protocol chain — OODS quotient check, K parametric line-fold rounds with Fiat-Shamir alphas and index derivation, constant last-layer polynomial check (reconstructs expected Merkle root and asserts it equals `friLayerRoots[K]`).

Remaining for production: non-constant last-layer bounded-degree check (MVP-4 final).

### 2. Aggregator trust model

Off-chain signature verification runs outside the STARK proof (pre-proof cross-check).

**Planned mitigation:**
- Fraud proofs
- Permissionless aggregators

### 3. Adoption timeline

PQ adoption is inevitable, but gradual.

**Focus areas:** CBDCs, government systems, long-term archival infrastructure.

---

## Economics (Draft)

- Users pay a fee for batch inclusion
- Aggregators receive rewards proportional to gas saved vs naive verification
- Future: fraud-proof penalties, decentralized aggregator market

---

## Future Extensions

- Threshold signatures (`t-of-n`)
- Multi-party aggregation
- Non-constant last FRI layer: on-chain bounded-degree polynomial check (MVP-4 final)
- FRI blowup ≥ 8 for mainnet (LOG_BLOWUP=6 → 130-bit soundness already achieved)
- Native PQ rollup chain

---

## Why Now

- NIST finalized PQC standards (FIPS 203–205, 2024)
- Quantum threat: "harvest now, decrypt later" is active
- Stwo deployed on Starknet Mainnet (November 2025)
- PQ migration window is open — but narrowing

### External Validation (May 2026)

Quantus published *"The State of Quantum: What Crypto Can't Afford to Ignore"* (May 27, 2026), independently confirming the same problem QLSA solves:

> *"A standard ECDSA transaction carries roughly 97 bytes of signature and public key. The same transaction using ML-DSA-87 carries almost 7187 bytes — a 74× increase that would sharply minimise the number of transactions per block without architectural changes."*

Their proposed solution: **STARK-style proof aggregation + Poseidon2** to move verification off-chain.

This is exactly QLSA's architecture — Circle STARK (Stwo) + Poseidon2 OODS sponge + O(1) on-chain verification. The key architectural difference: Quantus builds a new L1 blockchain requiring bootstrap from scratch; QLSA is a **drop-in aggregation layer** on top of existing chains (Ethereum, no hard-fork required).

Source: Quantus, *"The State of Quantum: What Crypto Can't Afford to Ignore"*, May 27, 2026.

---

## Contributing

Early-stage deep-tech research project.

Looking for contributors in: Cryptography, ZK / STARKs, Blockchain infrastructure.

---

## License

Apache 2.0

---

**Disclaimer:** QLSA is experimental research software. Do not use in production systems.
