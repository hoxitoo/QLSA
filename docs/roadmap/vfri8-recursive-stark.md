# Roadmap: VFRI8 (Poseidon2 Trace Commitment) + Recursive STARK

> Записано: 2026-06-07. Автор: совместный анализ команды.

## Контекст и проблема

QLSA достигает **130-bit soundness off-chain** (LOG_BLOWUP=6, N_FRI_QUERIES=20, POW_BITS=10),
но on-chain верификация — только 1 FRI-запрос (~16-bit soundness). Полная 20-запросная
Blake2s-верификация стоит ~300M gas (20 запросов × 2 пути × depth=10 × ~800K gas/путь),
что в 10× превышает block limit Ethereum (~30M gas).

**Принятое решение**: пропустить промежуточные шаги и сразу реализовать:

1. **VFRI8 — Poseidon2 trace commitment** (замена Blake2s → Poseidon2 в Merkle + Fiat-Shamir канале)
   → 20-запросная on-chain верификация вписывается в **≤ 15M gas на Ethereum mainnet**
2. **Recursive STARK** (доказательство доказательства) → константный on-chain cost **~5M gas**,
   независимо от количества FRI-запросов, глубины дерева и версии STARK

---

## Экспертная оценка

### VFRI8 — Poseidon2 Trace Commitment

#### Сильные стороны

**Газ: качественный скачок**

| | Blake2s | Poseidon2 | Выигрыш |
|---|---|---|---|
| 1 Merkle-путь (depth=10) | ~800K gas | ~10K gas | **80×** |
| 20 запросов × 2 дерева | ~160M gas | ~400K gas | **400×** |
| Итог (оба LOG-группы) | >300M gas | **~6–8M gas** | **в лимит 15M ✓** |

- **Solidity-сторона уже реализована**: `Poseidon2M31.sol` с `compress()` (~1000 gas/permute)
  написан, cross-checked против Rust, 16 тестов проходят. Снимает ~30% риска.
- **Stwo поддерживает замену**: `CommitmentSchemeProver<CpuBackend, Blake2sM31MerkleChannel>` —
  оба параметра заменяются на Poseidon2-версии. Архитектурно предусмотрено.
- **Algebraic hash = нативная совместимость с рекурсией**: Poseidon2 описывается простыми
  полиномиальными ограничениями над M31 (~7 AIR-столбцов). Blake2s потребовал бы тысячи XOR-гейтов.
- **Инкрементально**: VFRI7 остаётся нетронутым. Параллельные верификаторы на период миграции.

#### Слабые стороны и риски

**1. Главный риск: синхронизация leaf-encoding**

Stwo хеширует листья как `Blake2s(uint32_words_le)`. Poseidon2 оперирует парами M31-элементов.
Если Rust и Solidity используют разный порядок слов или padding — всё сломается бесшумно.

*Решение*: до написания прувера — зафиксировать спецификацию:
`hashLeaf([w0,w1,...]) = compress(compress(w0,w1), compress(w2,w3))...`
и верифицировать тестовыми векторами независимо с обеих сторон.

**2. Transcript несовместимость с VFRI7**

VFRI8 использует другой Fiat-Shamir канал → другие query indices → все VFRI7-фикстуры
недействительны. Нужно регенерировать ВСЕ тестовые фикстуры.

*Решение*: держать VFRI7 и VFRI8 как параллельные верификаторы. `BatchRegistryV4` продолжает
работать. `BatchRegistryV5` использует VFRI8. Плавная миграция.

**3. Криптографическое замечание: Poseidon2 vs Blake2s**

Blake2s — консервативный хеш с 25+ годами криптоанализа. Poseidon2 — алгебраически
структурированный, разработан в 2019–2023. С 8 full rounds над M31 считается безопасным
(используется в StarkNet, Polygon zkEVM, Miden), но имеет меньший track record.

*Важно для продакшна*: перед деплоем на Ethereum mainnet — внешний аудит Poseidon2M31
параметров или верификация соответствия эталонным параметрам (HorizenLabs/Poseidon2 spec).

**4. Stwo upstream: нет официального Poseidon2Channel**

`Blake2sM31Channel` — из официального Stwo 2.2.0. Poseidon2Channel — кастомный.
При обновлении Stwo upstream — нужна ручная адаптация.

*Решение*: контрибьютировать Poseidon2Channel в Stwo upstream.

---

### Recursive STARK

#### Сильные стороны

- **Константный газ навсегда**: ~5M gas, независимо от количества FRI-запросов, размера трейса,
  версии STARK. Это архитектурный предел — лучше невозможно без trusted setup.
- **Нет trusted setup**: Stwo — transparent STARK, рекурсивный верификатор тоже в Stwo →
  нет "toxic waste", нет церемонии. Принципиально для trustless-системы.
- **Poseidon2 AIR уже есть**: `poseidon2_merkle_air.rs` уже реализован. Это самая дорогая
  часть рекурсивного верификатора — Merkle path verification через Poseidon2 AIR.
- **Futureproof**: новые версии STARK (V24, V25) автоматически получают константный on-chain cost.

#### Слабые стороны и риски

**1. Сложность реализации: ОЧЕНЬ ВЫСОКАЯ**

Рекурсивный верификатор — это вся логика `QLSAVerifierVFRI8.sol`, переведённая в AIR-ограничения:

| Операция | Строк AIR |
|---|---|
| QM31.mul(a, b) | ~4 |
| circleFold(f+,f-,α,y) | ~32 |
| Merkle path (depth=10) | ~70 |
| OODS quotient check | ~64 |
| **20 запросов, 9 fold rounds** | **~50K–200K строк AIR** |

Время доказательства: ~2–20 секунд.

**2. Bootstrapping correctness problem**

Если в VFRI8-верификаторе есть баг — рекурсивная схема молча принимает неверные доказательства.

*Решение*: строжайшее тестирование VFRI8 до начала рекурсии. 100+ rejection tests.
Формальная верификация критических операций (QM31.mul, circleFold, Merkle) идеальна.

**3. QLSAVerifierRecursive.sol = постоянный trust anchor**

Нельзя обновить без breaking change. Нужен аудит: $50–200K.

*Критически важно*: если рекурсивный верификатор неверен — злоумышленник может подать
поддельный recursive proof, который проходит on-chain, но не соответствует реальным ML-DSA подписям.

**4. Двухфазная стратегия рекурсии**

- Фаза A: доказать VFRI8-верификацию только для LOG=10 группы → один recursive proof
- Фаза B: объединить LOG=10 и LOG=8 recursive proofs через мета-схему → единый on-chain proof

---

## Ключевые экспертные замечания

1. **Не пропускай intermediate step: сначала N=5, потом N=20.** Начни с 5 запросов (~2M gas) →
   убедись что архитектура правильная → масштабируй до 20. Снижает риск неправильного leaf-encoding.

2. **Cross-check vector — это не тест, это MVP.** До написания Rust-кода VFRI8 — напиши
   Solidity-тест с hardcoded Poseidon2-значением, потом Rust-тест, генерирующий то же значение.
   Только при совпадении — начинай интеграцию.

3. **BatchRegistryV5 должен поддерживать оба верификатора (V7 + V8)** для плавной миграции.

4. **Газ-запас важен.** Estimate 6–8M gas. Реально может быть 10–12M из-за abi.decode overhead,
   calldata decoding, storage writes. Запас до 15M — достаточный.

5. **SNARK-рекурсия — альтернатива.** Groth16 даёт ~200 gas on-chain (single pairing check).
   Но требует trusted setup. Рекомендация: оставаться с STARK-рекурсией для trustlessness.

---

## Implementation Roadmap

```
Неделя 1–2: VFRI8 Rust-сторона
  ├── stark_stwo/src/poseidon2_channel.rs (NEW)
  │   ├── Poseidon2M31MerkleHasher: impl MerkleHasher
  │   ├── Poseidon2M31Channel: impl Channel
  │   └── Leaf encoding specification (фиксируем формат до кода)
  ├── Cross-check: Rust vs Solidity на 5 тестовых векторах
  ├── stark_stwo/src/vfri8_bridge.rs (NEW, адаптация vfri7_bridge.rs)
  └── stark_stwo/src/lib.rs: Poseidon2 type aliases + VFRI8 export functions

Неделя 2–3: VFRI8 Solidity-сторона
  ├── contracts/src/verifier/MerkleVerifier.sol
  │   └── hashPair/hashLeaf → Poseidon2M31.compress()
  ├── contracts/src/verifier/TwoChannel.sol
  │   └── _blake2sM31 → Poseidon2 sponge
  ├── contracts/src/QLSAVerifierVFRI8.sol (NEW, copy VFRI7 + swap backends)
  └── E2E test: 5-query proof генерация + on-chain верификация

Неделя 3–4: Scale up + интеграция
  ├── stark/prover.py: gen_mldsa_v23_vfri8_hints, gen_mldsa_v23_vfri8_cross_bound_hints
  ├── contracts/src/BatchRegistryV5.sol (NEW)
  ├── 20-query E2E тест + газ-репорт (цель: ≤ 15M gas)
  └── SDK: sdk/python/qlsa/models.py (has_vfri8), sdk/js/src/types.ts

Неделя 5–6: СТАБИЛИЗАЦИЯ (критически важна перед рекурсией)
  ├── 100+ rejection tests (каждое поле в hints должно отклоняться при изменении)
  ├── Fuzzing VFRI8 verifier
  └── Документация: leaf encoding spec, hints format, transcript order

Недели 7–14: Recursive STARK
  ├── Нед 7–9: stark_stwo/src/recursive_verifier.rs (NEW)
  │   ├── QM31 arithmetic AIR (mul, add, inv)
  │   ├── circleFold AIR, lineFold AIR
  │   ├── Merkle path AIR (через poseidon2_merkle_air.rs ✓)
  │   └── FRI fold chain AIR
  ├── Нед 10–11: stark_stwo/src/recursive_bridge.rs (NEW)
  │   └── prove_vfri8_recursive() + stark/prover.py wrapper
  ├── Нед 12–13: contracts/src/QLSAVerifierRecursive.sol (NEW)
  │   └── ~5M gas constant on-chain verification
  └── Нед 14: E2E финал
      ML-DSA подпись → V23 STARK → VFRI8 → Recursive → on-chain 5M gas ✓

Аудит (параллельно, до mainnet):
  └── Poseidon2M31 параметры + QLSAVerifierVFRI8 + QLSAVerifierRecursive
```

---

## Критические файлы для изменений

### Phase 1 (VFRI8)

| Файл | Изменение |
|------|-----------|
| `stark_stwo/src/poseidon2_channel.rs` | **NEW** — Poseidon2M31Channel + MerkleHasher |
| `stark_stwo/src/lib.rs` | Poseidon2 type aliases + VFRI8 bridge functions |
| `stark_stwo/src/vfri8_bridge.rs` | **NEW** — адаптация vfri7_bridge.rs |
| `contracts/src/verifier/MerkleVerifier.sol` | hashPair/hashLeaf → Poseidon2 |
| `contracts/src/verifier/TwoChannel.sol` | _blake2sM31 → Poseidon2 sponge |
| `contracts/src/QLSAVerifierVFRI8.sol` | **NEW** — copy VFRI7 + swap hash backends |
| `contracts/src/BatchRegistryV5.sol` | **NEW** — copy V4 + VFRI8 addresses |
| `stark/prover.py` | gen_mldsa_v23_vfri8_hints, gen_mldsa_v23_vfri8_cross_bound_hints |
| `sdk/python/qlsa/models.py` | has_vfri8 в WitnessStatus, BatchStatus |
| `aggregator/node.py` | VFRI8 witness/batch status |
| `tests/test_stark_stwo.py` | VFRI8 structural + 20-query gas tests |
| `contracts/test/QLSAVerifierVFRI8E2E.test.js` | **NEW** — E2E с 20-query fixture |

### Phase 2 (Recursive)

| Файл | Изменение |
|------|-----------|
| `stark_stwo/src/recursive_verifier.rs` | **NEW** — verifier AIR circuit |
| `stark_stwo/src/recursive_bridge.rs` | **NEW** — recursive proof generation |
| `stark/prover.py` | prove_vfri8_recursive() |
| `contracts/src/QLSAVerifierRecursive.sol` | **NEW** — recursive STARK verifier |
| `contracts/src/BatchRegistryV6.sol` | **NEW** — accepts recursive proof |

---

## Существующий reusable код

| Файл | Что переиспользовать |
|------|---------------------|
| `stark_stwo/src/poseidon2.rs` | `compress(left, right) -> u64` — напрямую в Poseidon2Channel |
| `stark_stwo/src/poseidon2_merkle_air.rs` | `build_merkle_tree()` — в recursive circuit |
| `contracts/src/verifier/Poseidon2M31.sol` | `compress()`, `sponge()` — в MerkleVerifier/TwoChannel |
| `stark_stwo/src/vfri7_bridge.rs` | copy + adapt → vfri8_bridge.rs |
| `contracts/src/QLSAVerifierVFRI7.sol` | copy + replace hash backends → VFRI8 |
| `contracts/src/BatchRegistryV4.sol` | copy + update verifier addresses → V5 |

---

## Мультичейн развёртывание

| Блокчейн | Реализуемость | Срок | Примечание |
|---|---|---|---|
| Arbitrum One | ✅ Тривиально | 1–2 дня | 1.125B gas block limit → 20-query Blake2s уже вписывается |
| Base / Optimism / Polygon | ✅ Тривиально | 1 день | Та же Solidity |
| zkSync Era / Scroll | ✅ Легко | 2–3 дня | EVM-compatible |
| StarkNet | 🟡 Возможно | 2–4 недели | Cairo 1.0, Poseidon нативен, рекомендуется |
| Sui / Aptos | 🟡 Возможно | 3–4 недели | Move, u256 нативно |
| Polkadot/Substrate | 🟡 Возможно | 3–5 недель | Rust pallet, нативная интеграция с Stwo |
| Solana | 🔴 Сложно | 4–8 недель | BPF compute limit → после рекурсии (5M gas ≈ 1.4M CU) |
| Bitcoin | ❌ Невозможно | — | Script не тьюринг-полный, нет пути |

**Стратегия**:
1. Сейчас: задеплоить VFRI7 на Arbitrum One — работает уже сегодня без изменений
2. После VFRI8: деплой на все EVM L2 — 1 день, максимальный охват
3. После рекурсии: Solana (recursive proof = ~5M gas = ~1.4M BPF CU, вписывается)
4. StarkNet: высокий приоритет (ZK-native chain, аудитория совпадает)

---

## Gas targets

| Конфигурация | Blake2s | Poseidon2 (VFRI8) | Цель |
|---|---|---|---|
| 1 запрос, 1 LOG-группа | ~8M gas | ~300K gas | — |
| 20 запросов, 1 LOG-группа | ~160M gas | ~3–4M gas | ≤ 15M ✓ |
| 20 запросов, 2 LOG-группы | >300M gas | **~6–8M gas** | **≤ 15M ✓** |
| Recursive STARK (после Phase 2) | — | **~5M gas** | **Константа ✓** |

---

## Команды для верификации

```bash
# Rust тесты (включая Poseidon2Channel)
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml

# Python тесты
pytest tests/ -v

# Solidity тесты + газ-репорт
cd contracts && npx hardhat test

# TypeScript SDK тесты
cd sdk/js && npm test

# E2E сухой прогон
python -m testnet.e2e --txs 8 --dry-run
```
