# QLSA — Project Context

## Статус
- Фаза: 1 — Криптографическое ядро
- Готово: структура проекта, requirements.txt, .gitignore
- В работе: core/keys.py
- Следующий шаг: core/signing.py

## Стек (актуально на апрель 2026)

### Фаза 1–2 (криптоядро + прототип)
- Python 3.10+
- liboqs-python >= 0.14.0 (liboqs 0.15.0)
- SHA3-512 (hashlib — стандартная библиотека)
- pytest >= 8.0

### Фаза 2 (STARK circuit — разработка/изучение)
- Winterfell v0.13.1 (Rust, MIT)
- ВНИМАНИЕ: Winterfell НЕ имеет perfect zero-knowledge
- Использовать только для прототипирования AIR-схем

### Фаза 2+ (STARK circuit — production)
- Stwo (Circle STARK, Rust, Apache 2.0)
- Запущен на Starknet Mainnet ноябрь 2025
- В 10-1000x быстрее Stone/Winterfell
- Поддерживает кастомный AIR (не только Cairo)
- GitHub: github.com/starkware-libs/stwo

### Фаза 3 (смарт-контракты)
- Solidity + Hardhat
- Stwo on-chain verifier (без trusted setup)
- Деплой: Polygon zkEVM или Starknet L2

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

## Архитектура QLSA

## Ключевые решения
- Подпись: ML-DSA-65 (NIST FIPS 204)
- Merkle хэш: SHA3-512
- STARK prover: Winterfell (прото) → Stwo (prod)
- Адрес: SHA3-256(pubkey) — pubkey скрыт до подписи
- Батч: 3000 транзакций по умолчанию
- Proof size цель: ~90KB константа

## Открытые вопросы
- AIR-схема для ML-DSA верификации в Winterfell/Stwo
- Интеграция Stwo кастомного AIR (не Cairo)
## Архитектурные решения (обновлено)
- public_inputs содержит ТОЛЬКО roots (не массивы pubkeys)
- MVP-1: ML-DSA + Merkle без STARK
- MVP-2: STARK для Merkle
- MVP-3: ML-DSA внутри AIR (главная новизна, Фаза 3)
- Fraud-proof модель — future feature (Фаза 4+)
- Batch economics — future feature (Фаза 4+)

## Benchmark цели (измерять с первого дня)
- proof_size vs N (100, 500, 1000, 3000 tx)
- merkle_build_time vs N
- verify_time vs N
- gas_cost (после контрактов)