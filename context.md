# QLSA — Project Context

## Статус (обновлено 2026-06-03)

- Фаза: **MVP-5 завершён** (2026-05-25) + **V23 dual-VFRI7 production pipeline с cross-proof binding**
- Все Phase 1–6, MVP-3, MVP-3+, V22, V23, VFRI4/VFRI5/VFRI6/VFRI7, BatchRegistryV4 — завершены полностью
- QLSAVerifierVFRI7: `mixRoot(merkleRoot)` перед `drawQueries`; BatchRegistryV4 использует cross-bound roots
- Aggregator, HTTP API, Python SDK, TypeScript SDK — обновлены под VFRI7 dual-commitment
- Проведён аудит безопасности + code review (2026-05-25); 5 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-05-30 round-1); 8 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-05-30 round-2); 11 новых findings — все устранены
- Проведён аудит безопасности + code review (2026-06-03); 2 новых findings — все устранены

### Что готово

#### Core / Aggregator / SDK
- `core/keys.py` — ML-DSA-44/65/87 keygen, derive_address (SHA3-256), wipe_key
- `core/signing.py` — sign / verify через liboqs
- `core/transaction.py` — Transaction dataclass, детерминированная сериализация, tx_hash
- `core/merkle.py` — SHA3-512 Merkle tree, build / root / proof / verify
- `core/batch.py` — create_batch, merkle_root_onchain()
- `aggregator/` — Mempool (thread-safe), Batcher (min_batch_size, force_batch), AggregatorNode
- `aggregator/api.py` — HTTP API (FastAPI): `/transactions`, `/batch/run`, `/batch/flush`, `/stats`, `/health`, `GET /batch/{batch_id}`
  - Rate limiting: per-IP sliding-window (100 tx/min, 20 batch ops/min)
  - `AggregatorNode._history` capped at 1000 entries (evict oldest) — memory-safe for long-running nodes
  - `TRUSTED_PROXIES` конфигурируется через одноимённую env var (по умолчанию: 127.0.0.1, ::1)
- `sdk/python/qlsa/` — Wallet, LocalClient, HttpClient, WitnessStatus, BatchStatus
  - `prove_witness(tx, n_fri_queries=1)` — локальный ML-DSA witness без обращения к серверу
  - `get_batch(batch_id)` — получить BatchStatus по ID (LocalClient и HttpClient)
  - `WitnessStatus.fri_security_bits` — вычисляется как `6 × n_fri_queries + 10`
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
- `BatchRegistryV2.sol` — `submitBatchWithNonces()`: строгий порядок nonce per sender; `MAX_SENDERS=3000`
- `BatchRegistryV3.sol` — IQLSAVerifierV4 interface + queryHints; `MAX_SENDERS=3000`
- `BatchRegistryV4.sol` — dual-VFRI7: LOG=10 + LOG=8 cross-bound proofs; `MAX_SENDERS=3000`; `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)`
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

#### Тесты (актуально 2026-06-03)
- Python: **239 тестов** (без PyO3) / **~325** (с PyO3 ext)
- Rust: **210 тестов** (cargo test, non-ignored) + **85 ignored** (slow STARK integration tests incl. V23)
- TypeScript SDK: **25 тестов** (jest; обновлены для VFRI7 dual-commitment fields)
- Solidity/Hardhat: **847 тестов** — все проходят
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
