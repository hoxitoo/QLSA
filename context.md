# QLSA — Project Context

## Статус (обновлено 2026-06-10, вечер — VFRI9)

- Фаза: **VFRI9 завершён** (2026-06-10) — last-layer FRI check + широкие (62-бит) Poseidon2 узлы + полное поглощение корней в Fiat-Shamir. Soundness-аргумент он-чейн FRI протокола завершён.
- **VFRI9**: `QLSAVerifierVFRI9.sol`, `Poseidon2MerkleVerifierW.sol` (62-бит узлы: `(s0<<32)|s1`), `Poseidon2Channel.mixRootW/mixRootFull`
  - Last-layer check: прувер передаёт все `2^(treeDepth−K)` оценок финального FRI-слоя; верификатор строит Merkle-дерево и сверяет с `friLayerRoots[K]` — закрыт пробел soundness VFRI5–VFRI8
  - Wide nodes: коллизия узла 2^15.5 → 2^31 (максимум для t=2; 128-бит требует t≥4/RPO256)
  - Full-root absorption: `mixRootFull` поглощает все 32 байта trace root и batch merkle root (VFRI8 поглощал только 4 младших байта)
  - ABI хинтов (6 head slots): `abi.encode(uint128, uint128, bytes32, uint128[] lastLayerEvals, bytes32[], QueryHints[])`; маркер версии proof[0:8]=3
  - BatchRegistryV5 принимает VFRI9 через конструктор/`setVerifier` — новый реестр не нужен
- **VFRI9 Rust bridges**: `gen_vfri9_hints_from_cols_nfolds`, `gen_mldsa_v23_vfri9_hints[_log8]`, `gen_mldsa_v23_vfri9_cross_bound_hints`
- **VFRI9 Python wrappers**: `prove_mldsa_sig_vfri9_stark` → `FullV23VFRI9CrossBoundHintResult`
- **Живучесть агрегатора (2026-06-10)**: восстановление после краха прувера (транзакции возвращаются в мемпул, ≤3 retry на батч, затем unproven-батч для liveness); `ProverUnavailableError` отличает «расширение не установлено» от «прувер упал»; `prepend_batch` возвращает потерянные tx (oldest-kept) + метрика `dropped_count`; валидация `mempool_capacity >= min_batch_size`
- **API auth (2026-06-10)**: Bearer-token (`QLSA_API_TOKEN`) на `POST /batch/run`/`/batch/flush`, constant-time сравнение; без переменной — открыто с warning при старте
- **Hardhat разблокирован локально**: в кэше `~/.cache/hardhat-nodejs/compilers-v2/linux-amd64/` лежал WASM `soljson-*.js` под видом нативного бинаря (источник EPIPE); создан маркер `*.does.not.work` → hardhat использует WASM fallback; полный набор контрактных тестов работает локально
- Все Phase 1–6, MVP-3, MVP-3+, V22, V23, VFRI4/VFRI5/VFRI6/VFRI7/VFRI8/VFRI9, BatchRegistryV4/V5 — завершены
- **VFRI8**: `QLSAVerifierVFRI8.sol`, `BatchRegistryV5.sol`, `Poseidon2MerkleVerifier.sol`, `Poseidon2Channel.sol`
- **Rust bridges**: `gen_mldsa_v23_vfri8_hints`, `gen_mldsa_v23_vfri8_hints_log8`, `gen_mldsa_v23_vfri8_cross_bound_hints`
- **Python wrappers**: `prove_mldsa_sig_vfri8_stark` → `FullV23VFRI8CrossBoundHintResult`
- **Aggregator/SDK**: `BatchResult.has_vfri8`, vfri8_* fields, API endpoint, SDK client
- **Tests**: 552 Python (incl. 11 VFRI9) / 350 без PyO3, 303 Rust (+88 ignored), 906 Hardhat (incl. 21 VFRI9 E2E), ~71 TS; fixtures `full_v23_vfri8_cross_bound_e2e.json` + `full_v23_vfri9_cross_bound_e2e.json`
- Проведён аудит безопасности + code review (2026-05-25); 5 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-05-30 round-1); 8 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-05-30 round-2); 11 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-06-03); 2 новых findings — все устранены
- **Аудит безопасности + code review (2026-06-10)**: 21 finding (3C + 5H + 7M + 6L из code audit; 2C + 4H + 3M + 3L из security audit) — 18 устранены, 3 задокументированы как known limitations
- SDK расширен (2026-06-04): `Wallet.is_wiped` + знак после wipe, `TransactionBuilder.reset_nonce()`, `HttpClient.wait_for_batch()`, `AggregatorClient.waitForBatch()`, `GET /batches`
- Transaction tracking (2026-06-04): `GET /transaction/{tx_hash}`, `TransactionStatus`, `get_transaction()` в Python + TS SDK; `tx_hash` в SubmitResult/SubmitResponse
- Mempool visibility (2026-06-05): `GET /mempool?limit`, `GET /batch/{id}/transactions`; `MempoolStatus`; `get_mempool()` + `get_batch_transactions()` Python + TS; fix `LocalClient.get_batch()` O(n)→O(1)
- Code quality (2026-06-05): `DuplicateTxError` mempool deduplication; mypy clean; `python -m aggregator` entry point; `py.typed` PEP 561 marker
- CI fix (2026-06-06): `aggregator/__main__.py` — bandit B104 false positive suppressed (`# nosec B104`) для intentional `0.0.0.0` bind (конфигурируется через `--host`/`HOST`)

### Что готово

#### Core / Aggregator / SDK
- `core/keys.py` — ML-DSA-44/65/87 keygen, derive_address (SHA3-256), wipe_key
- `core/signing.py` — sign / verify через liboqs
- `core/transaction.py` — Transaction dataclass, детерминированная сериализация, tx_hash
- `core/merkle.py` — SHA3-512 Merkle tree, build / root / proof / verify
- `core/batch.py` — create_batch, merkle_root_onchain()
- `aggregator/` — Mempool (thread-safe), Batcher (min_batch_size, force_batch), AggregatorNode
- `aggregator/api.py` — HTTP API (FastAPI): `/transactions`, `/batch/run`, `/batch/flush`, `/stats`, `/health`, `GET /batch/{batch_id}`, `GET /batches`, `GET /transaction/{tx_hash}`
  - Rate limiting: per-IP sliding-window (100 tx/min, 20 batch ops/min, 200 reads/min)
  - `AggregatorNode._history` capped at 1000 entries (evict oldest) — memory-safe for long-running nodes
  - `TRUSTED_PROXIES` конфигурируется через одноимённую env var (по умолчанию: 127.0.0.1, ::1)
  - `Mempool._tx_hashes` — O(1) pending-status lookup by tx_hash
  - `AggregatorNode._tx_to_batch` — O(1) batched-status lookup by tx_hash (evicted with batch)
- `sdk/python/qlsa/` — Wallet, LocalClient, HttpClient, WitnessStatus, BatchStatus
  - `prove_witness(tx, n_fri_queries=1)` — локальный ML-DSA witness без обращения к серверу
  - `get_batch(batch_id)` — получить BatchStatus по ID (LocalClient и HttpClient)
  - `WitnessStatus.fri_security_bits` — вычисляется как `6 × n_fri_queries + 10`
  - `Wallet.is_wiped` + ValueError при `sign_transaction()` после `wipe()`
  - `TransactionBuilder.reset_nonce(n=0)` — сбросить auto-nonce счётчик
  - `HttpClient.wait_for_batch(batch_id, timeout, poll_interval)` — polling до появления батча
  - `HttpClient.history(limit)` — список батчей (newest-first, limit 1–200)
  - `LocalClient/HttpClient.get_transaction(tx_hash)` → `TransactionStatus` (pending/batched/unknown)
  - `SubmitResult.tx_hash` — 64-char hex hash, set when accepted=True
  - `TransactionStatus(tx_hash, status, batch_id?)` — новый датакласс
- `sdk/js/src/` — TypeScript SDK: AggregatorClient, AggregatorHttpError, types
  - `AggregatorClient.waitForBatch(batchId, {timeoutMs, pollIntervalMs})` — polling helper
  - `AggregatorClient.listBatches(limit)` — список батчей
  - `AggregatorClient.getTransaction(txHash)` → `TransactionStatus`
  - `AggregatorHttpError` — типизированная ошибка с `status: number`
  - `SubmitResult.txHash` — 64-char hex hash from `/transactions` response

#### STARK / Rust
- `stark_stwo/src/mldsa/` — чистый Rust ML-DSA-65 верификатор (FIPS 204 Algorithm 3)
  - `params.rs` — k=6, l=5, η=4, τ=49, β=196, γ₁=2¹⁹, d=13, λ=192, ω=55
  - `field.rs` / `ntt.rs` / `poly.rs` / `polyvec.rs` / `encoding.rs` / `xof.rs` / `verify.rs`
- `stark_stwo/src/lib.rs` — все PyO3 биндинги + Rust-уровневые prove/verify функции
- `stark_stwo/src/mldsa_verify_stark.rs` — полная ML-DSA arithmetic STARK pipeline:

#### Эволюция witness pipeline (MVP-3+)

Sub-proof reduction roadmap — каждая версия уменьшает число FRI commitments:

| Версия | Sub-proofs | Описание |
|--------|-----------|----------|
| V17 | 5 | AllNtt + AzCt1 + CombinedInttWPrime + NormUseHint |
| V18 | 4 | AllNtt + AzCt1 + InttWPrime(merged) + NormUseHint |
| V19 | 3 | NttAzCt1(merged) + InttWPrime + NormUseHint |
| V20 | 2 | NttAzCt1 + INTT+WPrime+Norm+UH(merged) |
| **V21** | **1** | **Все 7 компонентов в одном STARK** — теоретический минимум |
| **V22** | **1** | **V21 + Merkle root как public input** — security upgrade |
| **V23** | **1** | **V22 + RangeQBatch (288 cols)** — az_hat ∈ [0,Q), closes soundness gap |

**V23 — текущая production версия (2026-05-20):**
- `VerifyMldsaProofV23` — единый proof (8-компонентный STARK, 3504 main columns + 1 preproc)
- `prove_verify_mldsa_v23(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)`
- `verify_mldsa_witness_v23(proof)` — верификация всего пайплайна
- Proof криптографически привязан к: ML-DSA challenge (c_tilde) + Merkle root батча
- RangeQBatch закрывает soundness gap AzFull: az_hat[j][p] ∈ [0, Q)

Column layout V23 STARK (Tree 1, 3504 cols + 1 preproc):
```
NttBatch    LOG=10  649  cols  — NTT(z,c,t1) → z_hat, c_hat, t1_hat
AzFull      LOG=8  1523  cols  — A×z в NTT domain → az_hat
Ct1Full     LOG=8   295  cols  — c·t1 в NTT domain → ct1_hat
InttBatch   LOG=10  649  cols  — INTT(az_hat, ct1_hat) → az_out, ct1_out
WPrimeFull  LOG=8    24  cols  — w' = az - ct1
NormCheck   LOG=8    15  cols  — ‖z‖∞ per coefficient
UseHintV2   LOG=8    61  cols  — UseHint(w', hints) → w1_prime  [+1 preproc]
RangeQBatch LOG=8   288  cols  — az_hat[j][p] ∈ [0, Q) для K=6 полиномов  ← NEW
```

**V22 (предыдущая версия):** 7-компонентный STARK, 3216 main cols + 1 preproc

`stark/prover.py` — Python обёртки V4..V23: `prove_mldsa_witness_stark_vN`, `verify_mldsa_witness_stark_vN`, `verify_mldsa_hash_check`

#### AIR Circuits (MVP-3+ — полностью завершены)

| Circuit | Файл | Статус | Что доказывает |
|---------|------|--------|----------------|
| NTT-batch | `mldsa_verify_stark.rs` | ✅ Done | NTT(z,c,t1) в NTT domain корректен |
| INTT-batch | `mldsa_verify_stark.rs` | ✅ Done | Inverse NTT + fingerprint binding |
| Az-full | `mldsa_az_full_air.rs` | ✅ Done | A·z matrix-vector product в NTT domain |
| Ct1-full | `mldsa_ct1_full_air.rs` | ✅ Done | c·t1 в NTT domain |
| WPrime-full | `mldsa_wprime_full_air.rs` | ✅ Done | w' = az_out - ct1_out |
| NormCheck-batch | `mldsa_norm_check_batch_air.rs` | ✅ Done | ‖z[i]‖∞ = min(z[i], Q−z[i]) |
| UseHintBatchV2 | `mldsa_use_hint_batch_air.rs` | ✅ Done | UseHint(h, r) = w1 (с preproc) |
| Q-range check | `range_check_air.rs` | ✅ Done | v ∈ [0, Q) via 23-bit decomp |
| c_tilde binding | `lib.rs` | ✅ Done | c̃ mixed в Fiat-Shamir до Tree0 commit |
| **Merkle root binding** | `lib.rs` | ✅ Done | merkle_root mixed в Fiat-Shamir (V22) |
| **Единый STARK (V21/V22)** | `mldsa_verify_stark.rs` | ✅ Done | Все 7 компонентов → 1 FRI commitment |
| **RangeQBatch (V23)** | `lib.rs` / `mldsa_verify_stark.rs` | ✅ Done | az_hat[j][p] ∈ [0,Q) — 8-й компонент, закрывает AzFull soundness gap |

#### Contracts
- `BatchRegistry.sol` — v1, `Ownable`, `nonReentrant`, `BatchAlreadyFinalized` replay guard
- `BatchRegistryV2.sol` — `submitBatchWithNonces()`: строгий порядок nonce per sender; `MAX_SENDERS=3000`
- `BatchRegistryV3.sol` — IQLSAVerifierV4 interface + queryHints; `MAX_SENDERS=3000`
- `BatchRegistryV4.sol` — dual-VFRI7: LOG=10 + LOG=8 cross-bound proofs; `MAX_SENDERS=3000`; `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)`; proof length guards (C3 fix)
- `BatchRegistryV5.sol` — dual-VFRI8: identical to V4 but uses `QLSAVerifierVFRI8`; proof length guards; cross-proof binding unchanged
- `QLSAVerifierVFRI8.sol` — VFRI7 + Poseidon2 Merkle + Poseidon2Channel; `_verifyOODS` returns (ok, fPlus, fMinus) instead of mutating struct (H4 fix)
- `verifier/Poseidon2MerkleVerifier.sol` — Poseidon2 binary Merkle (rate-1 sponge leaf, compress pair)
- `verifier/Poseidon2Channel.sol` — Poseidon2 duplex sponge Fiat-Shamir channel
- `QLSAVerifier.sol` — заглушка (всегда true)
- `QLSAVerifierV2.sol` — M31 структурный верификатор
- `QLSAVerifierV3.sol` — MIN_PROOF_LENGTH=700, Blake2s imported
- `QLSAVerifierFull.sol` — onchain_commitment = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]
- `QLSAVerifierVFRI4.sol` — Poseidon2 OODS sponge; y=0 guard in _checkCircleFold
- `QLSAVerifierVFRI5.sol` — compRoot Merkle tree (eliminates per-query O(n_cols)); y=0 guard
- `QLSAVerifierVFRI6.sol` — off-chain OODS combo (O(1) gas for any n_cols); y=0 guard
- `QLSAVerifierVFRI7.sol` — VFRI6 + `mixRoot(merkleRoot)` before `drawQueries`; cross-proof binding
- `M31.sol` — field arithmetic library
- `Blake2s.sol` — Blake2s-256 (RFC 7693, pure Solidity)

#### Тесты (актуально 2026-06-10)
- Python: **336 тестов** (без PyO3) / **528** (с PyO3 ext) — включает 11 новых VFRI8 тестов
- Rust: **210 тестов** (cargo test, non-ignored) + **85 ignored** (slow STARK integration tests incl. V23)
- TypeScript SDK: **~71 тестов** (jest; +13 новых для waitForBatch/getTransaction/getMempool/getBatchTransactions)
- Solidity/Hardhat: **847 тестов** — все проходят (Hardhat native solc недоступен в dev среде; node.js solc компилирует без ошибок)
- mypy --strict: `core/ aggregator/` (exclude `aggregator/api`) — чистые

#### Деплой
- Сеть: **Ethereum Sepolia** (2026-05-05)
- Первый батч финализирован: 4 транзакции, 3234 байт proof, 9.16 секунды
- `testnet/e2e.py` — end-to-end тест с реальными подписями

---

## Стек (актуально на май 2026)

### Фаза 1–2 (криптоядро + STARK)
- Python 3.10+
- liboqs-python **0.14.1** (PyPI) + liboqs C **0.14.0**
- SHA3-512 (Merkle), SHA3-256 (адреса), Blake2s-256 (commitment binding)
- pytest, mypy, bandit, pip-audit

### Фаза 2 (STARK circuit)
- **Stwo 2.2.0** (Circle STARK, Rust nightly-2025-07-01, Apache 2.0) — **активно**
- AIR constraints: hash chain `H(a,b) = a³ + b` над M31 (прото, не крипто-стойкий)
- ML-DSA arithmetic circuits: **10/10 реализованы** (V22 — 1 sub-proof)
- FRI blowup=64, N_FRI_QUERIES=20, POW_BITS=10 → **130-bit soundness** ✅
- Winterfell v0.13.1 — архив, не используется активно

### Фаза 3 (смарт-контракты)
- Solidity + Hardhat + OpenZeppelin v5
- Сеть: Ethereum Sepolia testnet

---

## Ключевые алгоритмы (актуально NIST 2025)

### ИСПОЛЬЗОВАТЬ
- ML-DSA-65 → FIPS 204 (подписи, основной)
- SLH-DSA → FIPS 205 (хэш-based, долгосрочный архив)
- ML-KEM-768 → FIPS 203 (обмен ключами)

### НЕ ИСПОЛЬЗОВАТЬ (устарело/удалено)
- ~~Dilithium3/5~~ — удалён в liboqs 0.15.0
- ~~SPHINCS+~~ — заменён SLH-DSA
- ~~ECDSA~~ — квантово-уязвим

---

## Архитектура QLSA

### Слой 1 — Подписи
- ML-DSA-65 (FIPS 204)
- Адрес = SHA3-256(pubkey)

### Слой 2 — Агрегация
1. Collect txs (Mempool → Batcher)
2. Verify ML-DSA-65 (Rust FIPS 204, вне AIR — cross-checked off-circuit)
3. Build SHA3-512 Merkle tree → `merkle_root`
4. Generate STARK proof (V22) — все 7 arithmetic circuits в одном FRI commitment
   - Transcript: `c_tilde` → `merkle_root` → Tree0(preproc) → Tree1(3216 cols) → fingerprints
5. `onchain_commitment` = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]

### Слой 3 — Верификация
- **BatchRegistryV4.sol** (dual-VFRI7): `submitBatch(merkleRoot, commit10, proof10, hints10, commit8, proof8, hints8)`
  - Cross-bound roots: `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)`, `boundRoot8 = keccak256(batchRoot ‖ traceRoot10)`
  - Каждый VFRI7 вызов ≤ 15M gas; calldata ~12.5 KB совокупно
- `QLSAVerifierVFRI7.sol`: полный FRI протокол с cross-proof binding
- Merkle root + оба commitment хранятся on-chain (nonce-ordered replay protection)

---

## MVP план

| MVP | Статус | Детали |
|-----|--------|--------|
| MVP-1 | ✅ Done | ML-DSA + Merkle без STARK |
| MVP-2 | ✅ Done | STARK hash chain prover (Stwo) |
| SDK | ✅ Done | Python + JS + HTTP API |
| MVP-3 | ✅ Done | ML-DSA batch verifier (Rust FIPS 204) + STARK bridge |
| Phase 6 | ✅ Done | Sepolia testnet, первый батч финализирован 2026-05-05 |
| **MVP-3+** | **✅ Done** | **Все 7 AIR circuits → 1 STARK proof (V22) + Merkle root binding** |
| **V23** | **✅ Done** | **RangeQBatch 8th circuit (az_hat ∈ [0,Q)) + security hardening** |
| **VFRI4/5/6** | **✅ Done** | **O(1)-gas on-chain verifier; 1298 и 2206 cols ≤ 15M gas** |
| **BatchRegistryV4** | **✅ Done** | **Dual-VFRI7 registry; full V23 trace coverage; 847 tests** |
| **MVP-5** | **✅ Done** | **VFRI7 cross-proof binding + aggregator/SDK wiring + security audit (2026-05-25)** |
| **VFRI8** | **✅ Done** | **Poseidon2 trace commitment; ≤15M gas for 20 queries; aggregator/SDK wired (2026-06-10)** |
| **VFRI9** | **✅ Done** | **Last-layer FRI check + wide Poseidon2 nodes + full-root Fiat-Shamir (2026-06-10)** |
| MVP-4 | ⏳ Future | Recursive STARK (constant ~5M gas); RPO256 hash AIR (128-bit nodes) |

---

## Незавершённые дела (не блокируют MVP-4)

> Записано 2026-06-06. Выполнить в удобный момент — не критично для production, но улучшают качество.

| # | Задача | Приоритет | Сложность | Описание |
|---|--------|-----------|-----------|----------|
| 1 | `bytes(private_key)` иммутабельная копия | Средний | Высокая | `wipe_key()` обнуляет основной буфер, но Python-side копия liboqs — best-effort. Нужна Rust-обёртка с `SecureZeroingMemory` / custom allocator |
| 2 | tx_hash усечён до 31 бита для M31 | Низкий | Средняя | tx_hash = SHA3-256 (32 байта = 256 бит), но при вставке в M31 коммитмент берётся только 31 бит. Нужно либо расширить commitment до 256 бит, либо явно задокументировать как design decision |
| 3 | Prometheus metrics endpoint | Низкий | Низкая | `GET /metrics` — gauges: `mempool_size`, `batches_total`, `proofs_total`, `pending_transactions`. Нужен для мониторинга production-нод |
| 4 | WebSocket/SSE для real-time обновлений | Низкий | Средняя | `GET /events/batch/{id}` и `GET /events/transaction/{hash}` — SSE stream статусов. Клиенты смогут избежать polling |
| 5 | Автоматизированные benchmarks | Средний | Низкая | `bench_core.py`, `bench_stark.py` существуют но не запускались системно. Нужен CI job + результаты в README для: proof_size(N), merkle_time(N), witness_prove_time |
| 6 | E2E тесты на живом Sepolia | Средний | Средняя | `testnet/e2e.py` запускается вручную. Нужен автоматизированный режим: submit → batch → verify on-chain, результат в CI как scheduled job |
| 7 | Docker Hub image | Низкий | Низкая | `docker build` работает локально, но нет published image. Нужен `ghcr.io/hoxitoo/qlsa-aggregator:latest` с автопушем из CI |

---

## Открытые вопросы

### Архитектурные (критично)
- **ML-DSA верификация в AIR** — ✅ **Закрыт** (V21: все 7 circuits в 1 STARK, 2026-05-16)
- **Merkle-root не публичный вход STARK** — ✅ **Закрыт** (V22: mixed в Fiat-Shamir, 2026-05-16)
- **M31 wrap-around soundness** — ✅ **Закрыт** (Q-range check AIR, 2026-05-14)
- **c_tilde не привязан к STARK** — ✅ **Закрыт** (Fiat-Shamir mixing, 2026-05-14)
- **Replay-защита on-chain** — ✅ **Закрыто** (`submitBatchWithNonces()` BatchRegistryV2.sol)

### Реализационные
- Замена `H(a,b) = a³ + b` на RPO256 или Poseidon2 — отложено до MVP-4
- FRI blowup=4 (~60-бит soundness) — для mainnet нужен blowup≥8 (MVP-4)
- Полный on-chain FRI верификатор (~5K строк Solidity) — MVP-4
- `wipe_key()` в Python: `bytes(private_key)` создаёт иммутабельную копию — для production нужна Rust-обёртка с SecureZeroingMemory
- tx_hash усекается до 31 бита для M31 коммитмента

### Инфраструктурные
- CI: Python джобы — сборка liboqs из исходников в GitHub Actions
- Выбор mainnet L2: Ethereum + Sepolia ✅, будущий mainnet TBD

---

## Безопасность

### Реализованные меры
- Приватные ключи: только `bytearray`, `wipe_key()` обнуляет после использования (best-effort)
- Тесты: эфемерные ключи, никаких hardcoded секретов
- Логирование: только публичные данные
- RNG: только liboqs внутренний CSPRNG
- CI: bandit + pip-audit на каждый пуш
- Rate limiting: per-IP sliding-window (100 tx/min, 20 batch ops/min) — eviction thread-safe (2026-05-20)
- Nonce registry: `BatchRegistryV2.submitBatchWithNonces()` — строго возрастающий nonce per sender
- c_tilde binding: mixed в Fiat-Shamir channel до Tree0 commitment (V19+)
- Merkle root binding: mixed в Fiat-Shamir после c_tilde (V22) — proof специфичен для конкретного батча
- Q-range check AIR: закрывает soundness gap умножения в M31
- **RangeQBatch (V23)**: az_hat[j][p] ∈ [0, Q) для всех K=6 выходных полиномов AzFull (2026-05-20)
- **Constant-time Merkle verify**: `hmac.compare_digest` вместо `==` (2026-05-20)
- **X-Forwarded-For**: берётся rightmost IP (proxy-added), не первый (client-controlled) (2026-05-20)
- **Input validation**: `_validate_mldsa65_inputs` перед combined STARK prover calls (2026-05-20)
- **Solidity guards**: depth > 32 в MerkleVerifier; logDomainSize > 30 в V11/V12/V13; M31 range check в CM31 (2026-05-20)
- **MAX_SENDERS=3000**: `submitBatchWithNonces()` в V2/V3/V4 — ограничивает O(n²) dedup loop (2026-05-22)
- **History eviction**: `AggregatorNode._history` ограничена 1000 записями, oldest evicted (2026-05-22)
- **Circle fold y=0 guard**: `if (h.queryPointY == 0) return false` в VFRI4/VFRI5/VFRI6 (2026-05-22)
- **stark_stwo/target/ в .gitignore**: предотвращает случайный коммит больших Rust артефактов (2026-05-22)
- **Cross-proof binding (MVP-5)**: `QLSAVerifierVFRI7` mixит `merkleRoot` перед `drawQueries`; `BatchRegistryV4` передаёт `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)` — mixing proofs из разных witnesses ломает Merkle verification (2026-05-25)
- **ML-DSA key size validation**: `deserialize_public_key` проверяет размер после base64 decode (2026-05-25)
- **`_validate_senders` / `_as_bytes32` / `_decode_commitment16`**: строгая валидация входных данных в `submit.py` (2026-05-25)
- **TwoChannel logDomainSize guard**: `require(logDomainSize <= 31)` предотвращает uint256 overflow в `drawQueries` (2026-05-25)
- **TRUSTED_PROXIES configurable**: `_TRUSTED_PROXIES` в `aggregator/api.py` читается из env var — операторы могут добавлять reverse proxy без изменения кода (2026-05-30)
- **amount ≥ 1 validation**: `Transaction.__post_init__` отклоняет `amount=0` — устраняет тихое несоответствие между SDK и API (2026-05-30)
- **prepend_batch logging**: `Mempool.prepend_batch()` логирует warning при потере транзакций из-за переполнения (2026-05-30)
- **Dead code removal**: `Batch.stark_commitment_onchain()` удалён — всегда поднимал ValueError с реальными commitments (ожидал 8 hex символов, реальные — 32) (2026-05-30)
- **`wait_and_verify` exception safety**: `testnet/submit.py` — разделено получение receipt и проверка revert; только "not found" исключения перехватываются (2026-05-30)
- **GET /batch/{batch_id} endpoint**: новый endpoint позволяет SDK/клиентам опросить статус батча без повторного доказательства (2026-05-30)
- **WitnessStatus.fri_security_bits**: поле добавлено в Python SDK (parity с TypeScript SDK); вычисляется как `6 × n_fri_queries + 10` (2026-05-30)
- **requirements-dev.txt deduplicated**: дубликаты `fastapi` / `httpx` заменены на `-r requirements-api.txt` (2026-05-30)
- **TRUSTED_PROXIES IP validation**: `ipaddress.ip_address()` проверяет каждый токен; невалидные — warning+skip (2026-05-30)
- **public_key/signature normalize**: API-validators возвращают `.lower()` для hex-полей — консистентность с sender/recipient (2026-05-30)
- **GET /batch/* rate limiting**: 200 req/min per IP; устраняет O(n) history-scan DoS вектор (2026-05-30)
- **batch_id UUID validation**: `uuid.UUID(batch_id)` guard, HTTP 400 на невалидный формат (2026-05-30)
- **Transaction.public_key size validation**: `__post_init__` проверяет размер против ML-DSA {1312,1952,2592} байт (2026-05-30)
- **create_batch() algorithm validation**: ранняя проверка до первого `verify()` вызова (2026-05-30)
- **node._history → deque + _batch_index**: `deque(maxlen=1000)` устраняет slice allocation; dict обеспечивает O(1) lookup (2026-05-30)
- **N_FRI_QUERIES env validation**: try/except ValueError + range [1,64] check при инициализации узла (2026-05-30)
- **batcher.py module logger**: заменён root logger на `logging.getLogger(__name__)` (2026-05-30)
- **HttpClient.submit() KeyError guard**: защита от серверных ответов без поля `accepted` (2026-05-30)
- **`HttpClient._decode_json()`**: обёртка `resp.json()` перехватывает `json.JSONDecodeError` — nginx/cloudflare могут вернуть HTML body с 2xx при рестарте; все 7 call-сайтов обновлены (2026-06-03)
- **`testnet/e2e.py` sender_key**: дублировал вычисление SHA3-256(public_key) через `hashlib`, хотя `tx.sender` уже содержит это значение как hex; удалён лишний `import hashlib` (2026-06-03)
- **Dead `_call_prover` удалён** (C1 fix, 2026-06-10): функция никогда не вызывалась; `_call_prover_p2` получил commitment-length guard (`len != 32`)
- **`num_folds_log8` silent drop fix** (C2 fix, 2026-06-10): `gen_mldsa_v23_vfri7/8_cross_bound_hints` теперь использует `num_folds_log10 if not None else num_folds_log8`
- **Proof length guard in BatchRegistryV4/V5** (C3 fix, 2026-06-10): `if (proofLog10.length < 40) revert` перед assembly calldataload — предотвращает second-preimage на cross-bound root
- **Rate limiting `/stats` и `/node/config`** (H2 fix, 2026-06-10): добавлены в `_RateLimitMiddleware.dispatch` под `_read_windows` (200 req/min)
- **`_verifyOODS` не мутирует `h`** (H4 fix, 2026-06-10): возвращает `(bool, fPlus, fMinus)` вместо записи в `h.compValue`; убраны тавтологические проверки `mul(a/b, b)==a`
- **VFRI8 `witness_commitment` fallback** (H5 fix, 2026-06-10): если VFRI7 не установил `witness_commitment`, VFRI8 fallback `result.witness_commitment = vr8.log10_commitment`
- **`_sender_txs` memory leak fix** (M6 fix, 2026-06-10): `AggregatorNode._record` при eviction батча удаляет tx_hash из `_sender_txs`; пустые deque удаляются из dict

### Таблица рисков (обновлено 2026-05-30)

| Риск | Уровень | Статус |
|------|---------|--------|
| ML-DSA верификация вне AIR circuit | Критично | ✅ Закрыт (V21: 1 STARK, 2026-05-16) |
| Merkle-root не публичный вход STARK | Критично | ✅ Закрыт (V22: Fiat-Shamir, 2026-05-16) |
| AzFull soundness gap (az_hat не range-checked) | Высокий | ✅ Закрыт (V23: RangeQBatch 288 cols, 2026-05-20) |
| On-chain OODS O(n_cols) gas bottleneck | Высокий | ✅ Закрыт (VFRI6: off-chain combo, O(1) gas, 2026-05-22) |
| submitBatchWithNonces O(n²) без лимита senders | Средний | ✅ Закрыт (MAX_SENDERS=3000 в V2/V3/V4, 2026-05-22) |
| _history unbounded growth (memory leak) | Средний | ✅ Закрыт (cap 1000 + eviction, 2026-05-22) |
| Circle fold y=0 — M31.inv panic | Низкий | ✅ Закрыт (y==0 guard в VFRI4/5/6, 2026-05-22) |
| stark_stwo/target/ не в .gitignore | Низкий | ✅ Закрыт (.gitignore обновлён, 2026-05-22) |
| .env не имел DEPLOYER_PRIVATE_KEY alias | Баг | ✅ Закрыт (.env + submit.py исправлены, 2026-05-22) |
| Нет cross-proof binding между LOG=10 и LOG=8 | Средний | ✅ Закрыт (VFRI7: `mixRoot(merkleRoot)` + BatchRegistryV4 cross-bound roots, 2026-05-25) |
| `deserialize_public_key` принимал любой размер bytes | Средний | ✅ Закрыт (ML-DSA key size validation, 2026-05-25) |
| Dead code в `gen_mldsa_v23_vfri7_cross_bound_hints` (блок `pass`) | Низкий | ✅ Закрыт (ValueError при разных fold counts, 2026-05-25) |
| Молчаливое усечение sender bytes в `submit.py` | Средний | ✅ Закрыт (`_validate_senders` + `_as_bytes32` + `_decode_commitment16`, 2026-05-25) |
| `TwoChannel.drawQueries` overflow при logDomainSize >= 256 | Низкий | ✅ Закрыт (`require(logDomainSize <= 31)`, 2026-05-25) |
| n_queries=1 on-chain → 16-bit soundness (газовый лимит) | Высокий | Open (n конфигурируемо через N_FRI_QUERIES env var; gas opt деferred MVP-4) |
| QLSAVerifierFull — Blake2s binding (не полный FRI) | Критично | Partial (MVP-4: OODS + 20 queries) |
| FRI blowup=4 → ~60-бит soundness | Высокий | ✅ Закрыт (blowup=64, 20 queries, 10 pow → 130 bits) |
| M31 wrap-around soundness gap (mul constraints) | Высокий | ✅ Закрыт (Q-range check AIR, 2026-05-14) |
| c_tilde не привязан к STARK proof | Высокий | ✅ Закрыт (Fiat-Shamir mixing, 2026-05-14) |
| Нет replay-защиты on-chain | Высокий | ✅ Done (BatchRegistryV2 nonce registry) |
| Не constant-time сравнение Merkle root | Средний | ✅ Закрыт (hmac.compare_digest, 2026-05-20) |
| X-Forwarded-For spoofing в rate limiter | Средний | ✅ Закрыт (rightmost IP, 2026-05-20) |
| Race condition eviction в rate limiter | Средний | ✅ Закрыт (dict.pop + both windows, 2026-05-20) |
| Нет валидации k/l перед combined STARK | Средний | ✅ Закрыт (_validate_mldsa65_inputs, 2026-05-20) |
| MerkleVerifier некапсированная глубина (depth≥256 overflow) | Средний | ✅ Закрыт (depth > 32 guard, 2026-05-20) |
| CM31.fromBytes8LE нет M31 range check | Средний | ✅ Закрыт (require a < P && b < P, 2026-05-20) |
| treeDepth > 30 не проверялся в V11/V12/V13 | Низкий | ✅ Закрыт (logDomainSize > 30 guard, 2026-05-20) |
| Rate limiting отсутствует | Средний | ✅ Done (sliding-window per IP) |
| bytes(private_key) — иммутабельная копия в Python | Средний | Open (Rust wipe_bytes; Python-side copy неизбежна) |
| H(a,b) = a³+b — не крипто-стойкая | Низкий | ✅ Done (Poseidon2-over-M31, 2026-05-16) |
| tx_hash усекается до 31 бита для M31 | Низкий | Open |
| `TRUSTED_PROXIES` hardcoded — операторы не могли добавить свои reverse proxy | Средний | ✅ Закрыт (env var конфигурация, 2026-05-30) |
| `Transaction.amount = 0` принималось SDK, отклонялось API — тихое несоответствие | Средний | ✅ Закрыт (amount ≥ 1 в `__post_init__`, 2026-05-30) |
| `Mempool.prepend_batch()` молча дропал транзакции при переполнении | Средний | ✅ Закрыт (logging.warning при drop, 2026-05-30) |
| `Batch.stark_commitment_onchain()` dead code — всегда ValueError с реальными данными | Баг | ✅ Закрыт (метод удалён, 2026-05-30) |
| `wait_and_verify` перехватывал все Exception — маскировал сетевые ошибки | Средний | ✅ Закрыт (только "not found" перехватывается, 2026-05-30) |
| Нет `GET /batch/{id}` endpoint — нельзя получить статус батча без доказательства | Низкий | ✅ Закрыт (endpoint добавлен, 2026-05-30) |
| `WitnessStatus.fri_security_bits` отсутствовало в Python SDK | Низкий | ✅ Закрыт (поле добавлено, 2026-05-30) |
| Дублирование fastapi/httpx в requirements-dev.txt | Низкий | ✅ Закрыт (-r requirements-api.txt, 2026-05-30) |
| TRUSTED_PROXIES IP не валидировался — невалидный токен добавлялся в whitelist | Средний | ✅ Закрыт (ipaddress.ip_address() + warning, 2026-05-30) |
| public_key / signature в API не нормализовались к lowercase | Низкий | ✅ Закрыт (.lower() в validators, 2026-05-30) |
| GET /batch/* endpoints не rate-limited — DoS через O(n) history scan | Средний | ✅ Закрыт (200 req/min limit, 2026-05-30) |
| batch_id принимал любую строку — не валидировался как UUID | Низкий | ✅ Закрыт (uuid.UUID() guard, HTTP 400, 2026-05-30) |
| Transaction.public_key не проверялся на ML-DSA размер в `__post_init__` | Средний | ✅ Закрыт (size check против {1312,1952,2592}, 2026-05-30) |
| create_batch() algorithm не валидировался — ошибка появлялась на первом verify | Низкий | ✅ Закрыт (ранняя проверка, 2026-05-30) |
| node._history — slice eviction создавал новую list при каждом evict (memory + GC pressure) | Средний | ✅ Закрыт (deque(maxlen=1000) + _batch_index dict, 2026-05-30) |
| N_FRI_QUERIES env без обработки ошибок — crash при нечисловом значении | Средний | ✅ Закрыт (try/except + range [1,64], 2026-05-30) |
| batcher.py использовал root logger — нельзя фильтровать по модулю | Низкий | ✅ Закрыт (module logger, 2026-05-30) |
| HttpClient.submit() KeyError при ответе без поля accepted | Низкий | ✅ Закрыт (try/except guard, 2026-05-30) |
| `HttpClient` все методы — `json.JSONDecodeError` при HTML ответе от proxy с 2xx статусом | Средний | ✅ Закрыт (`_decode_json()` static method, все 7 call-сайтов, 2026-06-03) |
| `testnet/e2e.py` повторно вычислял `sender_key` через `hashlib.sha3_256()` — `tx.sender` уже содержит это значение | Низкий | ✅ Закрыт (`bytes.fromhex(tx.sender)` + удалён импорт, 2026-06-03) |
| Dead `_call_prover` — никогда не вызывался, скрывал commitment-length guard от активного пути | Критично | ✅ Закрыт (функция удалена; guard добавлен в `_call_prover_p2`, 2026-06-10) |
| `num_folds_log8` игнорировался если `num_folds_log10=None` в cross_bound_hints | Критично | ✅ Закрыт (`num_folds_log10 if not None else num_folds_log8`, VFRI7+VFRI8, 2026-06-10) |
| `calldataload(offset+8)` без проверки длины proof — second-preimage на cross-bound root | Критично | ✅ Закрыт (`if (proof.length < 40) revert` в V4 + V5, 2026-06-10) |
| `GET /stats` и `/node/config` не rate-limited — DoS вектор | Высокий | ✅ Закрыт (200 req/min limit, 2026-06-10) |
| `_verifyOODS` мутировал memory struct `h` — хрупкая зависимость от порядка вызовов | Высокий | ✅ Закрыт (возвращает `(bool, fPlus, fMinus)`, 2026-06-10) |
| VFRI8 success не обновлял `witness_commitment` — `has_witness=True` при `onchain_commitment=None` | Высокий | ✅ Закрыт (fallback `result.witness_commitment = vr8.log10_commitment`, 2026-06-10) |
| `_sender_txs` unbounded growth — каждый отправитель оставлял записи навсегда | Средний | ✅ Закрыт (cleanup при eviction батча, 2026-06-10) |
| Missing last-layer polynomial check (FRI soundness gap) в VFRI7/VFRI8 | Критично | ✅ Закрыт (QLSAVerifierVFRI9: `_checkLastLayer` rebuild + assert root == friLayerRoots[K], 2026-06-10). VFRI5–VFRI8 остаются в репо без проверки — только для регрессии, не деплоить |
| `submitBatchWithNonces` не проверяет что senders совпадают с транзакциями в батче | Высокий | Open (griefing attack requires valid proof; нет финансового риска для пользователей) |
| Poseidon2Channel t=2/M31 = 62-bit state (ниже 128-bit target sponge security) | Высокий | Частично смягчён (2026-06-10): VFRI9 wide nodes 31→62 бит (коллизия узла 2^15.5→2^31) + mixRootFull (полное поглощение 32-байтных корней). Полные 128 бит требуют t≥4/RPO256 — MVP-6 |
| Узлы Poseidon2 Merkle в VFRI8 = 31 бит (s0 only) — коллизия листа ~2^15.5 | Высокий | ✅ Закрыт в VFRI9 (`Poseidon2MerkleVerifierW`, узел = `(s0<<32)\|s1`); VFRI8 — регрессионный, не деплоить |
| Транзакции терялись при крахе прувера (батч с proof=None уходил в историю) | Высокий | ✅ Закрыт (Batcher retry ≤3 + возврат в мемпул через prepend_batch, 2026-06-10) |
| `prepend_batch` молча терял транзакции при переполнении мемпула | Средний | ✅ Закрыт (возврат списка потерянных, oldest-kept, метрика dropped_count, 2026-06-10) |
| Нет аутентификации на `/batch/run`/`/batch/flush` (compute DoS) | Высокий | ✅ Закрыт (Bearer-token `QLSA_API_TOKEN`, constant-time, opt-in, 2026-06-10) |
| `setVerifier()` без timelock — single-key upgrade risk | Средний | Open (research prototype; рекомендуется 48h timelock + multisig для mainnet) |
| No authentication on `/batch/run` и `/batch/flush` — DoS через compute drain | Высокий | Open (rate limiting 20 ops/min; Bearer token рекомендуется для mainnet) |
| Off-chain mempool accepts stale-nonce transactions | Средний | Open (per-sender nonce tracking рекомендуется для mainnet) |

---

## Конкурентный ландшафт (обновлено 2026-05-29)

### Quantus (май 2026)

**Статус**: опубликовали research report *"The State of Quantum: What Crypto Can't Afford to Ignore"* (27.05.2026).

**Их тезис**: ML-DSA-87 даёт 7187 байт на транзакцию (74× больше ECDSA) → без архитектурных изменений блокчейн не масштабируется.

**Их решение**: новый L1 с PQ из коробки. Технический стек: Plonky2 + STARK-style proof aggregation + Poseidon2 + Wormhole Addresses.

**Сравнение с QLSA**:

| Аспект | Quantus | QLSA |
|--------|---------|------|
| Архитектура | Новый L1 (bootstrap сообщества с нуля) | Aggregation layer поверх существующих сетей |
| Доказательная система | Plonky2 | Stwo Circle STARK |
| OODS hash | Poseidon2 | Poseidon2-over-M31 (идентично) |
| ML-DSA вариант | ML-DSA-87 | ML-DSA-65 (FIPS 204) |
| Статус | Research report / whitepaper | Working prototype, Sepolia testnet live |
| Барьер входа | Высокий (новый L1, нет liquidity) | Низкий (L2 на Ethereum, без хард-форка) |

**Вывод**: Quantus подтверждает правильность тезиса QLSA и выбора технического стека (STARK + Poseidon2). Ключевое преимущество QLSA — не нужен новый L1; агрегационный слой совместим с существующей инфраструктурой Ethereum.

### Ключевые упоминания (внешние источники)
- Quantus, *"The State of Quantum: What Crypto Can't Afford to Ignore"*, 27.05.2026
- ForkLog, Владимир Слипер, «В Quantus указали на неготовность крипторынка к квантовой угрозе», 28.05.2026
- IBM Quantum (май 2026): квантовые вычисления выходят из лабораторной стадии
- BIP-360: предложение по миграции биткоина к PQ-защите (Pay-to-Merkle-Root)

---

## Ключевые решения (design decisions)

- Подпись: ML-DSA-65 (NIST FIPS 204)
- Merkle хэш: SHA3-512 (вне STARK)
- STARK prover: Stwo 2.2.0 (Circle STARK, M31 field)
- Адрес: SHA3-256(pubkey)
- onchain_commitment: Blake2s(proof[:32] ∥ c_tilde[:32])[:16] — 128-bit binding
- c_tilde как публичный вход: mixed в Fiat-Shamir channel до Tree0 commit
- Merkle root как публичный вход: mixed в Fiat-Shamir после c_tilde (V22, 2026-05-16)
- Multi-component STARK: все компоненты в одном `prove(&[comp1, ..., comp7], channel, cs)`
- Mixed-size STARK: компоненты с разным LOG_N_ROWS в одном FRI — twiddles на max level
- extra_binding параметр: `prove_full_mldsa_witness_combined(…, c_tilde, extra_binding)` — V21 передаёт `&[]`, V22 передаёт `merkle_root`
- Q-range check: 48-column AIR (v, 23 bits of v, d=Q-1-v, 23 bits of d); C0 + 23 boolean + C24 + 23 boolean = 48 constraints
- Сериализация: bincode (Encode/Decode) для `[i64; 256]` — serde не поддерживает такие массивы
- Батч: до 3000 транзакций по умолчанию
- Деплой: Ethereum Sepolia (testnet)
- TraceLocationAllocator: `default()` для компонентов без preproc; `new_with_preprocessed_columns(&[pc_is_init_uh()])` когда UseHintBatchV2 включён
- `n_fri_queries`: конфигурируемо через `N_FRI_QUERIES` env var (default=1 → 16-bit on-chain soundness, gas-safe); `security_bits = 6 × n + 10`; n=20 → 130 bits но ~300M gas (deferred MVP-4)

---

## Зависимости

```
liboqs-python==0.14.1   # Python wrapper
# liboqs C 0.14.0        # собирается из исходников (cmake)
pytest==8.3.5
bandit==1.8.3
mypy==1.13.0
black==24.10.0
pip-audit==2.7.3
```

Rust: `nightly-2025-07-01` (зафиксирован в `stark_stwo/rust-toolchain.toml`)

---

## Benchmark цели

- `proof_size` vs N (100, 500, 1000, 3000 tx)
- `merkle_build_time` vs N
- `sign_time`, `verify_time` vs N
- `witness_prove_time` (V22 full witness latency)
- `gas_cost` (on-chain verification per batch)

Benchmarks: `benchmarks/bench_core.py`, `bench_stark.py`, `bench_poly_circuits.py`, `bench_witnesses.py`
