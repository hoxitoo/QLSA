# QLSA — Project Context

## Статус (обновлено 2026-05-14)

- Фаза: **Phase 6 завершена** (Sepolia, 2026-05-05) + **MVP-3+ в процессе** (7 из ~10 AIR circuits)
- Все Phase 1–6, MVP-3 — завершены полностью
- Следующий приоритет: MVP-3+ — замкнуть оставшиеся circuits, интегрировать в единый STARK proof

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
- `stark_stwo/src/mldsa_verify_stark.rs` — ML-DSA arithmetic STARK pipeline:
  - `AzProofV3` — 18 sub-proofs: L NTT + 1 Az-full + K INTT + K Q-range check
  - `VerifyMldsaProofV3` — 55 sub-proofs: AzProofV3 + poly_sub + norm_check + use_hint + hint_weight
  - `prove_verify_mldsa_v3(a_hat, z, c, t1, hints, k, l, c_tilde)` → `VerifyMldsaProofV3`
  - `verify_mldsa_witness_v3(proof)` → верификация всех sub-proofs
- `stark_stwo/src/range_check_air.rs` — **новый** Q-range check AIR (256 строк × 48 колонок)
- `stark/prover.py` — Python обёртки: `prove_mldsa_batch`, `prove_mldsa_sig_witness_stark`, `verify_mldsa_witness_stark`, `verify_mldsa_hash_check`

#### AIR Circuits (MVP-3+)

| Circuit | Файл | Статус | Что доказывает |
|---------|------|--------|----------------|
| NTT | `mldsa_verify_stark.rs` | ✅ Done | Forward NTT над Zq корректен |
| INTT | `mldsa_verify_stark.rs` | ✅ Done | Inverse NTT + fingerprint binding |
| PolyMul | `mldsa_verify_stark.rs` | ✅ Done | Coefficient-wise mul mod Q |
| PolyAdd | `mldsa_verify_stark.rs` | ✅ Done | Coefficient-wise add mod Q |
| NormCheck | `mldsa_verify_stark.rs` | ✅ Done | norm[i] = min(z[i], Q−z[i]) |
| UseHint | `mldsa_verify_stark.rs` | ✅ Done | UseHint(h, r) = w1 |
| Q-range check | `range_check_air.rs` | ✅ Done (2026-05-14) | v ∈ [0, Q) — 23-bit decomp + complement |
| Az-full (AzProofV3) | `mldsa_verify_stark.rs` | ✅ Done | Полное A·z matrix-vector product |
| c_tilde binding | `lib.rs` | ✅ Done (2026-05-14) | c̃ mixed в Fiat-Shamir до первого commitment |

#### Contracts
- `BatchRegistry.sol` — v1, `Ownable`, `nonReentrant`, `BatchAlreadyFinalized` replay guard
- `BatchRegistryV2.sol` — `submitBatchWithNonces()`: строгий порядок nonce per sender
- `QLSAVerifier.sol` — **заглушка** (всегда true)
- `QLSAVerifierV2.sol` — M31 структурный верификатор
- `QLSAVerifierV3.sol` — MIN_PROOF_LENGTH=700, Blake2s imported
- `QLSAVerifierFull.sol` — onchain_commitment = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]
- `M31.sol` — field arithmetic library
- `Blake2s.sol` — Blake2s-256 (RFC 7693, pure Solidity)

#### Тесты
- Python: **243 тестов** (pytest), все зелёные
- Rust: **181 тест** (cargo test), все зелёные
- TypeScript SDK: 31 тест (jest)
- Solidity: 155 тестов (hardhat)
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
- ML-DSA arithmetic circuits: 7 из ~10 реализованы
- **ВНИМАНИЕ: FRI blowup=4 → ~60-бит soundness** (для mainnet нужен ≥8)
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
2. Verify ML-DSA-65 (Rust FIPS 204, вне AIR)
3. Build SHA3-512 Merkle tree → `merkle_root`
4. Generate STARK proof → `onchain_commitment` = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]
5. Optional witness pipeline (MVP-3+): AzProofV3 (18 sub-proofs) + VerifyMldsaProofV3 (55 total)

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
| MVP-3+ | 🔄 50% | 7 AIR circuits готовы; интеграция + оставшиеся circuits в процессе |
| MVP-4 | ⏳ Future | Полный on-chain FRI верификатор (~5K строк Solidity), blowup≥8, RPO256 |

---

## Открытые вопросы

### Архитектурные (критично)
- **ML-DSA верификация в AIR** — 7 circuits готово, нужна финальная интеграция в один proof
- **Merkle-root не публичный вход STARK** — root не внутри proof; открыт вопрос о включении root chunks в public inputs AIR
- **M31 wrap-around soundness** — ✅ **Закрыт**: Q-range check AIR (23-bit decomp + complement d=Q-1-v) доказывает v ∈ [0, Q) для каждого Az[i]; реализован 2026-05-14
- **c_tilde не привязан к STARK** — ✅ **Закрыт**: c̃ mixed в Fiat-Shamir channel до первого trace commitment; разные c̃ → разные query positions → FRI fail; реализован 2026-05-14
- **Replay-защита on-chain** — ✅ **Закрыто**: `submitBatchWithNonces()` в BatchRegistryV2.sol; строго возрастающий nonce per sender

### Реализационные
- Замена `H(a,b) = a³ + b` на RPO256 или Poseidon2 — отложено до MVP-4
- FRI blowup=4 (~60-бит soundness) — для mainnet нужен blowup≥8 (MVP-4)
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
- Rate limiting: per-IP sliding-window (100 tx/min, 20 batch ops/min)
- Nonce registry: `BatchRegistryV2.submitBatchWithNonces()` — строго возрастающий nonce per sender
- c_tilde binding: Az-full Fiat-Shamir смешивает c̃ до первого commitment
- Q-range check AIR: закрывает soundness gap умножения в M31

### Таблица рисков (обновлено 2026-05-14)

| Риск | Уровень | Статус |
|------|---------|--------|
| ML-DSA верификация вне AIR circuit | Критично | 🔄 Partial (7 circuits, MVP-3+) |
| QLSAVerifierFull — Blake2s binding (не полный FRI) | Критично | Partial (MVP-4) |
| Merkle-root не публичный вход STARK | Критично | Open (MVP-3+) |
| FRI blowup=4 → ~60-бит soundness | Высокий | Partial (нужен blowup≥8, MVP-4) |
| M31 wrap-around soundness gap (mul constraints) | Высокий | ✅ Закрыт (Q-range check AIR, 2026-05-14) |
| c_tilde не привязан к STARK proof | Высокий | ✅ Закрыт (Fiat-Shamir mixing, 2026-05-14) |
| Нет replay-защиты on-chain | Высокий | ✅ Done (BatchRegistryV2 nonce registry) |
| Rate limiting отсутствует | Средний | ✅ Done (sliding-window per IP) |
| bytes(private_key) — иммутабельная копия в Python | Средний | Open (нужна Rust-обёртка, MVP-4) |
| H(a,b) = a³+b — не крипто-стойкая | Низкий | Принято для прото |
| tx_hash усекается до 31 бита для M31 | Низкий | Open |

---

## Ключевые решения (design decisions)

- Подпись: ML-DSA-65 (NIST FIPS 204)
- Merkle хэш: SHA3-512 (вне STARK)
- STARK prover: Stwo 2.2.0 (Circle STARK, M31 field)
- Адрес: SHA3-256(pubkey)
- onchain_commitment: Blake2s(proof[:32] ∥ c_tilde[:32])[:16] — 128-bit binding
- c_tilde как публичный вход: mixed в Fiat-Shamir channel до trace commitment
- Q-range check: 48-column AIR (v, 23 bits of v, d=Q-1-v, 23 bits of d); C0 + 23 boolean + C24 + 23 boolean = 48 constraints
- Сериализация: bincode (Encode/Decode) для `[i64; 256]` — serde не поддерживает такие массивы
- Батч: до 3000 транзакций по умолчанию
- Deплой: Ethereum Sepolia (testnet)

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
- `witness_prove_time` (MVP-3+, sub-proof latency)
- `gas_cost` (on-chain verification per batch)

Benchmarks: `benchmarks/bench_core.py`, `bench_stark.py`, `bench_poly_circuits.py`, `bench_witnesses.py`
