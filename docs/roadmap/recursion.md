# Roadmap: Proof Recursion (production gas target)

> Записано: 2026-06-17. Заменяет Phase 2 из `vfri8-recursive-stark.md`
> (Phase 1 / VFRI8 завершён; лестница t=2 → t=4 → t=8 завершена в VFRI10/VFRI11).

## Решение по пути (2026-06-17)

**Standalone t=16-верификатор (VFRI12) ПРОПУЩЕН.** Идём сразу к рекурсии.

| Вариант | Soundness узла | On-chain газ полного V23 | Вердикт |
|---------|---------------|--------------------------|---------|
| VFRI10 (t=4) | 2^31 | ~10–11M / группа, ≤16.7M через 2 tx | задеплоен (BatchRegistryV6) |
| VFRI11 (t=8) | 2^62 | **>100M** (depth-10) | только depth-4 toy verify==true |
| VFRI12 (t=16) | 2^124 ≈ 128-бит | **~400M+** (×4 от t=8) | ❌ никогда не задеплоит V23 |
| **Рекурсия** | 128-бит (inner hash любой) | **~5M константа** | ✅ цель |

**Вывод:** ширина перестановки поднимает стойкость, но НЕ снижает газовый бюджет —
он определяется глубиной дерева × числом FRI-запросов × числом fold-раундов. Единственный
способ получить и 128-бит, и production-газ — рекурсия: внешний proof константного размера,
а inner verifier circuit использует t=16/RPO256 бесплатно (стоимость уходит в prover, не on-chain).

## Архитектура

```
ML-DSA подпись
  → V23 STARK (8 AIR компонентов, 3504 cols)
  → VFRI11 hints (t=8 backend, 2^62 узлы)        ← inner proof (off-chain)
  → Recursive STARK: AIR, доказывающий "verify(VFRI11 hints) == true"
  → QLSAVerifierRecursive.sol: ~5M газа константа  ← on-chain
```

Рекурсивный верификатор — это вся логика `QLSAVerifierVFRI11.verify()`, переписанная как
набор AIR-ограничений над M31. Каждая операция верификатора становится строками трейса:

| Операция верификатора | AIR-gadget | Статус |
|----------------------|-----------|--------|
| QM31 add/mul (поле расширения) | `recursive/qm31_mul_air.rs` | ✅ **готов (2026-06-17)** |
| circleFold / lineFold | `recursive/fold_air.rs` | ✅ **готов (2026-06-17)** |
| OODS quotient check | `recursive/oods_air.rs` | ✅ **готов (2026-06-17)** |
| Poseidon2 Merkle path (inner hash) | `recursive/merkle_path_air.rs` (t=2) → t=16 вариант | ✅ **t=2 готов (2026-06-17)**; t=16 — R2 |
| Fiat-Shamir transcript replay | `recursive/channel_air.rs` (t=2) → t=16 вариант | ✅ **t=2 готов (2026-06-17)**; t=16 — R2 |
| FRI fold chain (K раундов) | `recursive/fri_chain_air.rs` | ⏳ цепочка fold-gadget |

## Поэтапный план

### Этап R0 — foundational gadgets (текущий)

Базовые AIR-примитивы, из которых собирается всё остальное. Каждый — самодостаточный,
с полным Stwo prove/verify roundtrip-тестом и кросс-чеком против u128-референса в `vfri2_bridge.rs`.

- **R0.1 QM31-mul AIR** (`recursive/qm31_mul_air.rs`) — ✅ **готов (2026-06-17)**
  - Доказывает `z = x · y` в QM31 = CM31[u]/(u²−R), R = 2+i, для батча операций
  - 12 cols (x:4, y:4, z:4), 4 ограничения степени 2, без preproc
  - Кросс-чек: trace.z == `qm31_mul` (u128-референс); полный prove/verify==true
- **R0.2 QM31-add/lin-combo AIR** — линейные комбинации `Σ αⱼ·colⱼ` (для OODS combo)
- **R0.3 Constraint-satisfaction harness** — ✅ **готов (2026-06-17)** — rejection-тесты в обоих
  gadget'ах: порча product/folded/helper-p в trace → proof не верифицируется (байтовый tamper +
  witness-level порча столбца через `prove_columns`). Подтверждает, что ограничения реально
  обеспечивают soundness (закрывает Low-1 аудита)

### Этап R1 — FRI fold + OODS gadgets

- **circleFold / lineFold** (`recursive/fold_air.rs`) — ✅ **готов (2026-06-17)**
  - Доказывает `folded = (f₊+f₋) + α·(f₊−f₋)·inv` для батча (одна формула на circle+line fold;
    inv = y⁻¹ или x⁻¹ передаётся как witness-столбец)
  - 21 col, helper `p = (f₊−f₋)·inv` снижает степень 3→2: C_p (4) + C_f (4), все степени 2
  - Кросс-чек: `fold_ref` ≡ `vfri2_bridge::circle_fold`; алгебраические инварианты (α=0 ⇒ sum;
    f₊=f₋ ⇒ 2·f₊); полный prove/verify roundtrip + 3 rejection-теста. 8 Rust тестов
- **OODS quotient** (`recursive/oods_air.rs`) — ✅ **готов (2026-06-17)**
  - Доказывает `fₚ·(px − z_x) = compValue − oodsCombo` (мультипликативная форма, без QM31-inv)
  - 17 col, 4 ограничения степени 2; `px` (M31) встраивается в QM31 как `(px,0,0,0)`; одна форма
    покрывает и позитивный (`px`), и антиподальный (`−px`) запрос
  - Кросс-чек против перегруппированного `vfri2_bridge` quotient `fPlus=(rawComp−oodsCombo)/(px−z_x)`;
    алгебраический инвариант (fₚ=0 ⇒ compValue=oodsCombo); roundtrip + 2 rejection. 8 Rust тестов
  - **R1 завершён** — все три арифметических FRI-примитива (QM31-mul, fold, OODS) готовы и
    cross-checked против on-chain референса. 24 рекурсивных Rust теста. Следующее: R2 (inner-hash)

### Этап R2 — Merkle path AIR + inner hash (t=16)

- **Merkle authentication-path AIR** (`recursive/merkle_path_air.rs`) — ✅ **t=2 готов (2026-06-17)**
  - Доказывает путь аутентификации: `leaf @ index + siblings → root` через Poseidon2 t=2 compression
    (on-chain `MerkleVerifier.verify` переведён в AIR; dual к full-tree `poseidon2_merkle_air`)
  - 10 main + 4 preproc col; раскладка 8 раундов/компрессия. Новые структурные элементы поверх
    раунд-ядра: выбор left/right по биту индекса (`bit·sib+(1−bit)·cur`), цепочка `cur` между
    компрессиями (`cur = is_first·leaf + (1−is_first)·s0[-1]`), привязка `(leaf,index,root)` в канал
  - Все ограничения ≤ степень 3 (как у базового Poseidon2 Merkle AIR)
  - Кросс-чек `merkle_path_root` против прямых `compress`; roundtrip depth 1/3/5; rejection
    (wrong root/index/tampered/corrupted-trace). 10 Rust тестов
  - **Самый дорогой блок рекурсивного верификатора** (один путь на запрос на FRI-слой)
- **Fiat-Shamir transcript replay** (`recursive/channel_air.rs`) — ✅ **t=2 готов (2026-06-17)**
  - Доказывает поглощение Poseidon2 t=2 duplex-губки (`mixU32s`-ядро `Poseidon2Channel`/`P2T8Channel`):
    `s0 += word; permute` на каждое слово → digest. Рекурсивный верификатор воспроизводит транскрипт
    в схеме, чтобы доказать честный вывод challenge'ов/позиций запросов (а не cherry-pick)
  - 7 main + 4 preproc col; init-wiring `inp0 = (is_first?0:s0[-1]) + word`, `inp1 = (is_first?0:s1[-1])`;
    привязка `(n_words, digest)` в канал. Кросс-чек против прямого `permute`; roundtrip 1/8 слов;
    rejection (wrong digest/count/tampered/corrupted-trace). 9 Rust тестов
- **t=16 inner hash** (остаток R2): расширить compression обоих inner-hash AIR (`merkle_path_air`,
  `channel_air`) до Poseidon2 t=16 (Stwo native, 128-бит). Ширина хеша — pluggable backend
  (как VFRI10→VFRI11 t=4→t=8); структура AIR не меняется. **Здесь t=16 «возвращается»** — но как
  inner circuit, on-chain газ не растёт

### Этап R3 — recursive verifier composition

> **Полный набор gadget'ов готов (2026-06-17):** арифметика (QM31-mul), FRI-фолд, OODS-quotient,
> inner-hash Merkle path, Fiat-Shamir transcript. 43 рекурсивных Rust теста. R3 собирает их в
> единый AIR.

- `recursive/recursive_verifier.rs` — собирает все gadgets в единый AIR верификатора VFRI11
- `recursive/recursive_bridge.rs` — `prove_vfri11_recursive(inner_proof, hints)` + PyO3
- Двухфазная стратегия: (A) recursive proof для LOG=10 группы; (B) мета-схема объединяет LOG=10+LOG=8

### Этап R4 — on-chain + интеграция

- `contracts/src/QLSAVerifierRecursive.sol` — верификация одного recursive STARK (~5M газа константа)
- `contracts/src/BatchRegistryV7.sol` — принимает recursive proof (один verify, одна tx)
- `stark/prover.py`: `prove_mldsa_sig_recursive_stark`; aggregator/SDK wiring
- E2E: ML-DSA подпись → V23 → VFRI11 → Recursive → on-chain ~5M газа ✓

## Критические замечания (перенесены из прежнего roadmap, актуальны)

1. **Bootstrapping correctness.** Если в VFRI11-верификаторе баг — рекурсия молча примет неверные
   доказательства. Перед R3 — строжайшее тестирование VFRI11 (rejection-тесты на каждое поле hints).
2. **QLSAVerifierRecursive = постоянный trust anchor.** Нельзя обновить без breaking change.
   Нужен внешний аудит до mainnet.
3. **Inner hash выбор.** t=16 Poseidon2 = нативный Stwo, дёшев для prover (x^5 forward S-box).
   RPO256 — альтернатива с консервативной стойкостью, но дороже в prover. Рекомендация: t=16.
4. **Газовый запас.** Цель ~5M, реально 5–8M из-за calldata/storage. Запас до 15M достаточен;
   на L2 (Arbitrum 1.125B block) — тривиально.
5. **Не пропускать intermediate scale.** Сначала рекурсия мини-proof (depth-4 VFRI11 fixture),
   затем full V23. Снижает риск ошибки в gadget-композиции.

## Переиспользуемый код

| Файл | Что переиспользовать |
|------|---------------------|
| `stark_stwo/src/poseidon2_merkle_air.rs` | Merkle path AIR (t=2) → шаблон для t=16 версии |
| `stark_stwo/src/vfri2_bridge.rs` | `qm31_mul/add/sub/inv`, `cm31_*`, `m31_*` — u128-референсы для кросс-чека gadgets |
| `stark_stwo/src/range_check_air.rs` | шаблон FrameworkEval + build_trace + тесты |
| `stark_stwo/src/lib.rs::make_config` | PcsConfig (LOG_BLOWUP=6, N_FRI_QUERIES=20, POW_BITS=10 → 130-бит) |
| `contracts/src/QLSAVerifierVFRI11.sol` | эталон логики, которую переводим в AIR |

## Команды верификации

```bash
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml recursive
pytest tests/ -v
cd contracts && npx hardhat test
```

Все изменения — на ветке `claude/review-repo-structure-E4kPW`; merge в main только по явному запросу.
