# QLSA — Project Context

## Статус (обновлено 2026-05-20)

- Фаза: **Phase 6 завершена** (Sepolia, 2026-05-05) + **V23 production pipeline** (8-component STARK)
- Все Phase 1–6, MVP-3, MVP-3+, V22, V23 — завершены полностью
- Проведён полный аудит безопасности + code review (2026-05-20); все findings зафиксированы
- Следующий приоритет: MVP-4 — RPO256 hash AIR + full V23 OODS wiring (20 queries, blowup 64)

### Что готово

#### Core / Aggregator / SDK
- `core/keys.py` — ML-DSA-44/65/87 keygen, derive_address (SHA3-256), wipe_key
- `core/signing.py` — sign / verify через liboqs
- `core/transaction.py` — Transaction dataclass, детерминированная сериализация, tx_hash
- `core/merkle.py` — SHA3-512 Merkle tree, build / root / proof / verify
- `core/batch.py` — create_batch, merkle_root_onchain(), stark_commitment_onchain()
- `aggregator/` — Mempool (thread-safe), Batcher (min_batch_size, force_batch), AggregatorNode
- `aggregator/api.py` — HTTP API (FastAPI): `/transactions`, `/batch/run`, `/batch/flush`, `/stats`, `/health`
  - Rate limiting: per-IP sliding-window (100 tx/min, 20 batch ops/min)
- `sdk/python/qlsa/` — Wallet, LocalClient, HttpClient, WitnessStatus, BatchStatus
  - `prove_witness(tx)` — локальный ML-DSA witness без обращения к серверу
- `sdk/js/src/` — TypeScript SDK: AggregatorClient, types

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
- `BatchRegistryV2.sol` — `submitBatchWithNonces()`: строгий порядок nonce per sender
- `QLSAVerifier.sol` — заглушка (всегда true)
- `QLSAVerifierV2.sol` — M31 структурный верификатор
- `QLSAVerifierV3.sol` — MIN_PROOF_LENGTH=700, Blake2s imported
- `QLSAVerifierFull.sol` — onchain_commitment = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]
- `M31.sol` — field arithmetic library
- `Blake2s.sol` — Blake2s-256 (RFC 7693, pure Solidity)

#### Тесты
- Python: ~249 тестов (pytest); 6 новых V23 Python тестов (2026-05-20)
- Rust: **210 тестов** (cargo test, non-ignored) + **85 ignored** (slow STARK integration tests incl. V23)
- TypeScript SDK: 31 тест (jest)
- Solidity: полный suite (hardhat) — все проходят после security fixes
- mypy --strict: все 16 файлов `core/ + aggregator/ + sdk/python/` чистые

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
- BatchRegistryV2.sol: `submitBatchWithNonces()` + nonce registry (replay protection)
- QLSAVerifierFull.sol: проверяет `onchain_commitment` (Blake2s binding)
- Merkle root хранится on-chain

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
| MVP-4 | ⏳ Future | RPO256 hash AIR + full V23 OODS wiring (20 queries, blowup 64) |

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

### Таблица рисков (обновлено 2026-05-20)

| Риск | Уровень | Статус |
|------|---------|--------|
| ML-DSA верификация вне AIR circuit | Критично | ✅ Закрыт (V21: 1 STARK, 2026-05-16) |
| Merkle-root не публичный вход STARK | Критично | ✅ Закрыт (V22: Fiat-Shamir, 2026-05-16) |
| AzFull soundness gap (az_hat не range-checked) | Высокий | ✅ Закрыт (V23: RangeQBatch 288 cols, 2026-05-20) |
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
