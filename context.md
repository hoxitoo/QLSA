# QLSA — Project Context

## Статус
- Фаза: **2 завершена** — STARK прототип
- Готово: Phase 1 (криптоядро) + Phase 2 (STARK прототип)
- Следующий шаг: Phase 3 — Smart Contracts (Solidity + Hardhat)

### Что готово
- `core/keys.py` — ML-DSA-44/65/87 keygen, derive_address (SHA3-256), wipe_key
- `core/signing.py` — sign / verify через liboqs
- `core/transaction.py` — Transaction dataclass, детерминированная сериализация, tx_hash
- `core/merkle.py` — SHA3-512 Merkle tree, build / root / proof / verify
- `core/batch.py` — create_batch: верификация подписей → Merkle root, поле stark_commitment
- `stark/` — STARK prover (Winterfell 0.13.1, Rust), Python subprocess обёртки
- `benchmarks/bench_core.py` — benchmark suite
- `tests/` — 68 тестов (57 core + 11 stark), все зелёные
- CI: `.github/workflows/ci.yml` — python (3.10/3.12) + rust джобы

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

### Фаза 2 (STARK circuit — прототип)
- Winterfell **v0.13.1** (Rust, MIT)
- **ВНИМАНИЕ: Winterfell НЕ имеет perfect zero-knowledge**
- Использовать только для прототипирования AIR-схем
- Хэш внутри STARK: `H(a,b) = a³ + b` (алгебраический прототип, **не криптографически стойкий**)
  - SHA3-512 нельзя эффективно выразить как AIR constraints (не алгебраическая функция)
  - Продакшн: заменить на Rescue Prime / RPO256 или ZK-friendly hash

### Фаза 2+ (STARK circuit — production)
- **Stwo** (Circle STARK, Rust, Apache 2.0)
- Запущен на Starknet Mainnet ноябрь 2025
- В 10–1000x быстрее Stone/Winterfell
- Поддерживает кастомный AIR (не только Cairo)
- GitHub: github.com/starkware-libs/stwo

### Фаза 3 (смарт-контракты)
- Solidity + Hardhat
- Stwo on-chain verifier (без trusted setup)
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
- Verify ML-DSA signatures (Python, вне STARK)
- Build SHA3-512 Merkle tree → `merkle_root`
- Hash chain STARK commitment → `stark_commitment`
- Generate STARK proof (Winterfell, hash chain AIR)

### Слой 3 — Верификация (следующий этап)
- On-chain STARK verifier (Solidity)
- BatchRegistry: хранит `merkle_root`
- Finalize batch

---

## Ключевые решения

- Подпись: ML-DSA-65 (NIST FIPS 204)
- Merkle хэш: SHA3-512 (вне STARK, для data availability)
- STARK prover: Winterfell (прото) → Stwo (prod)
- Адрес: SHA3-256(pubkey) — pubkey скрыт до подписи
- Батч: 3000 транзакций по умолчанию
- Proof size цель: ~90–200 KB (константа)
- public_inputs содержит ТОЛЬКО commitment (не массивы pubkeys)

### MVP план
- **MVP-1** ✅ — ML-DSA + Merkle без STARK (Phase 1, завершено)
- **MVP-2** ✅ — STARK hash chain prover (Phase 2, завершено)
  - Прим.: hash chain STARK (не Merkle-in-STARK) — SHA3-512 в AIR нецелесообразна
  - Переход на ZK-friendly hash (RPO256) запланирован при миграции на Stwo
- **MVP-3** — ML-DSA внутри AIR (главная новизна, Phase 3+)
- Fraud-proof модель — future feature (Phase 4+)
- Batch economics — future feature (Phase 4+)

---

## Открытые вопросы

- Замена прototipного хэша `H(a,b) = a³ + b` на RPO256 при переходе на Stwo
- Интеграция Stwo кастомного AIR (не Cairo)
- AIR-схема для ML-DSA верификации в Stwo (главная сложность MVP-3)
- Выбор L2: Polygon zkEVM vs Starknet (решить при старте Phase 3)
- CI: Python джобы — BuildIng liboqs из исходников в GitHub Actions

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

## Безопасность

- Приватные ключи: только `bytearray`, `wipe_key()` обнуляет после использования
- Тесты: эфемерные ключи, никаких hardcoded секретов в репозитории
- Логирование: только публичные данные (address, pubkey_hash, batch_id)
- RNG: только liboqs внутренний CSPRNG
- CI: bandit (статический анализ) + pip-audit (CVE scan) на каждый пуш
