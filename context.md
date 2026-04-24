# QLSA — Project Context

## Статус
- Фаза: **Phase 5 завершена** — SDK (Python + JS)
- Готово: Phase 1 (криптоядро) + Phase 2 (STARK прототип, Stwo) + Phase 3 (Smart Contracts) + Phase 4 (Aggregator) + Phase 5 (SDK)
- Следующий шаг: Phase 3+ (Stwo on-chain verifier) → MVP-3 (ML-DSA в AIR)

### Что готово
- `core/keys.py` — ML-DSA-44/65/87 keygen, derive_address (SHA3-256), wipe_key
- `core/signing.py` — sign / verify через liboqs
- `core/transaction.py` — Transaction dataclass, детерминированная сериализация, tx_hash
- `core/merkle.py` — SHA3-512 Merkle tree, build / root / proof / verify
- `core/batch.py` — create_batch, merkle_root_onchain(), stark_commitment_onchain()
- `stark/` — Winterfell prover (Python subprocess обёртки, устаревает)
- `stark_stwo/` — **Stwo Circle STARK prover** (Rust, nightly-2025-07-01), Python обёртки в `stark/prover.py` / `stark/verifier.py`
- `contracts/src/` — BatchRegistry.sol, QLSAVerifier.sol (**stub — всегда true**), IQLSAVerifier.sol (Hardhat + OZ v5)
- `aggregator/` — Mempool (thread-safe), Batcher, AggregatorNode (Phase 4)
- `benchmarks/bench_core.py` — benchmark suite
- `sdk/python/qlsa/` — **Python SDK**: Wallet, TransactionBuilder, LocalClient, HttpClient (Phase 5)
- `sdk/js/src/` — **JS SDK**: AggregatorClient (TypeScript, Phase 5)
- `aggregator/api.py` — HTTP API (FastAPI), запуск: `uvicorn aggregator.api:app`
- `tests/` — **124 теста** (core + stark + aggregator + sdk), все зелёные
- CI: python (3.10/3.12) + rust (nightly-2025-07-01) + contracts (Hardhat) джобы

---

## Стек (актуально на апрель 2026)

### Фаза 1–2 (криптоядро + STARK прототип)
- Python 3.10+
- liboqs-python **0.14.1** (PyPI) + liboqs C **0.14.0** (собирается из исходников)
  - Примечание: liboqs-python 0.15.x ещё не вышел на PyPI
  - liboqs C 0.15.0 существует как тег на GitHub, но соответствующего Python wrapper нет
  - liboqs-python 0.14.1 совместим с liboqs C 0.14.0 (проверено локально)
- SHA3-512 (hashlib — стандартная библиотека) — Merkle tree
- SHA3-256 (hashlib) — адресная схема
- pytest 8.3.5

### Фаза 2 (STARK circuit — текущий прототип)
- **Stwo 2.2.0** (Circle STARK, Rust nightly-2025-07-01, Apache 2.0) — **активно используется**
- Rust toolchain: `nightly-2025-07-01`
- AIR circuit: hash chain `H(a,b) = a³ + b` над M31 (Mersenne prime 2³¹−1)
- **ВНИМАНИЕ: Stwo НЕ имеет perfect zero-knowledge**
- **ВНИМАНИЕ: `H(a,b) = a³ + b` — не криптографически стойкая хэш-функция** (алгебраический прототип)
  - SHA3-512 нельзя эффективно выразить как AIR constraints (не алгебраическая функция)
  - Продакшн: заменить на Rescue Prime / RPO256 (ZK-friendly hash)
- Winterfell v0.13.1 сохранён в `stark/` (для архива, не используется активно)

### Фаза 3 (смарт-контракты)
- Solidity + Hardhat
- `QLSAVerifier.sol` — **заглушка** (не деплоить без реальной верификации)
- Stwo on-chain verifier (без trusted setup) — следующий этап
- Деплой: Polygon zkEVM или Starknet L2

---

## Ключевые алгоритмы (актуально NIST 2025)

### ИСПОЛЬЗОВАТЬ
- ML-DSA-65 → FIPS 204 (подписи, основной)
- ML-DSA-44 → FIPS 204 (лёгкий вариант)
- ML-DSA-87 → FIPS 204 (максимальная безопасность)
- SLH-DSA → FIPS 205 (хэш-based, долгосрочный архив)
- ML-KEM-768 → FIPS 203 (обмен ключами)

### НЕ ИСПОЛЬЗОВАТЬ (устарело/удалено)
- ~~Dilithium3/5~~ — удалён в liboqs 0.15.0
- ~~SPHINCS+~~ — удаляется в liboqs 0.16.0 (заменён SLH-DSA)
- ~~Stone Prover~~ — заменён Stwo
- ~~ECDSA~~ — квантово-уязвим

---

## Архитектура QLSA

### Слой 1 — Подписи (реализован)
- ML-DSA-65 (FIPS 204)
- Адрес = SHA3-256(pubkey)

### Слой 2 — Агрегация (реализован MVP)
- Collect transactions
- Verify ML-DSA signatures (Python, **вне STARK** — архитектурный gap до MVP-3)
- Build SHA3-512 Merkle tree → `merkle_root`
- Hash chain STARK commitment → `stark_commitment` (M31 field element, 4 bytes)
- Generate STARK proof (Stwo, hash chain AIR)

### Слой 3 — Верификация (следующий этап)
- On-chain STARK verifier (Solidity) — **stub, не готов**
- BatchRegistry: хранит `merkle_root`
- Finalize batch

---

## Ключевые решения

- Подпись: ML-DSA-65 (NIST FIPS 204)
- Merkle хэш: SHA3-512 (вне STARK, для data availability)
- STARK prover: Stwo 2.2.0 (Circle STARK)
- Адрес: SHA3-256(pubkey) — pubkey скрыт до подписи
- Батч: 3000 транзакций по умолчанию
- Proof size цель: ~90–200 KB (константа)
- public_inputs содержит commitment + log_size (не массивы pubkeys)

### MVP план
- **MVP-1** ✅ — ML-DSA + Merkle без STARK (Phase 1)
- **MVP-2** ✅ — STARK hash chain prover (Phase 2, Stwo)
  - Прим.: hash chain STARK (не Merkle-in-STARK) — SHA3-512 в AIR нецелесообразна
  - Переход на ZK-friendly hash (RPO256) запланирован при реализации MVP-3
- **SDK** ✅ — Python SDK + JS SDK + HTTP API (Phase 5)
- **MVP-3** — ML-DSA верификация внутри AIR (главная новизна, Phase 3+)
- Fraud-proof модель — future feature (Phase 4+)
- Batch economics — future feature (Phase 4+)

---

## Открытые вопросы

### Архитектурные (критично)
- **STARK не доказывает ML-DSA подписи** — главный архитектурный gap. AIR circuit доказывает лишь правильность цепочки H(a,b). Merkle-root не является публичным входом STARK — связь между proof и merkle_root отсутствует.
- **Replay-защита отсутствует** — одна транзакция (sender, nonce) может войти в несколько батчей; on-chain реестр использованных nonce не реализован.
- **M31-коммитмент — 32 бита** — пространство перебора ~2·10⁹, не является криптографически связывающим. При production-использовании заменить на хэш всего witness (SHA3-256 или BLAKE3).
- **AIR-схема для ML-DSA в Stwo** — главная сложность MVP-3 (NTT и решётчатая арифметика в constraints).

### Реализационные
- Замена прototipного хэша `H(a,b) = a³ + b` на RPO256 при переходе к MVP-3
- FRI blowup=2 (log_blowup_factor=1) → ~30-бит soundness; для production нужен blowup=4–8
- `wipe_key()` в Python ненадёжен: `bytes(private_key)` в `signing.py` создаёт иммутабельную копию, которую нельзя обнулить — для production нужна Rust-обёртка с `SecureZeroingMemory`
- `QLSAVerifier.verify()` — заглушка, всегда возвращает `true`; деплой на testnet недопустим
- `BatchRegistry.submitBatch()` — нет контроля доступа (любой адрес может финализировать root)
- Усечение tx_hash до 8 байт при конвертации в M31: из 256 бит SHA3-256 используется 31 бит

### Инфраструктурные
- CI: Python джобы — сборка liboqs из исходников в GitHub Actions
- Выбор L2: Polygon zkEVM vs Starknet (решить при старте Phase 3+)
- Интеграция Stwo кастомного AIR (не Cairo) — документация ограничена

---

## Benchmark цели (измерять с первого дня)

- `proof_size` vs N (100, 500, 1000, 3000 tx)
- `merkle_build_time` vs N
- `sign_time`, `verify_time` vs N
- `gas_cost` (после контрактов)

---

## Зависимости (зафиксированные версии)

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

## Безопасность

### Реализованные меры
- Приватные ключи: только `bytearray`, `wipe_key()` обнуляет после использования
- Тесты: эфемерные ключи, никаких hardcoded секретов в репозитории
- Логирование: только публичные данные (address, pubkey_hash, batch_id)
- RNG: только liboqs внутренний CSPRNG
- CI: bandit (статический анализ) + pip-audit (CVE scan) на каждый пуш
- Rust binary: входные данные (JSON/base64) обрабатываются через `match` без `.expect()` на untrusted input
- Subprocess: timeout 300s (prove) / 120s (verify), decode(errors='replace'), output validation

### Известные ограничения (требуют решения до production)
| Риск | Уровень | Статус |
|------|---------|--------|
| STARK не доказывает ML-DSA подписи | Критично | Open (MVP-3) |
| QLSAVerifier — stub (всегда true) | Критично | Open (Phase 3+) |
| Merkle-root не публичный вход STARK | Критично | Open (MVP-3) |
| M31-коммитмент 32 бита — не binding | Высокий | Open |
| bytes(private_key) — иммутабельная копия в Python | Высокий | Open (нужна Rust-обёртка) |
| Нет replay-защиты on-chain | Высокий | Open |
| FRI blowup=2 → ~30-бит soundness | Средний | Open |
| BatchRegistry без access control | Средний | Open |
| tx_hash усекается до 31 бита для M31 | Низкий | Open |
| H(a,b) = a³+b — не крипто-стойкая | Низкий | Принято для прото |
