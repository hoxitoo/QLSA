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
- **Wide inner hash — t=8 compression AIR** (`recursive/poseidon2_t8_air.rs`) — ✅ **готов (2026-07-13, R3.13)**
  - Первый широкий inner-hash: арифметизирует `compress_t8` (4-словные/124-битные узлы, коллизия ~2^62) —
    хеш, которым пользуется VFRI11 backend. 40 main + 11 preproc col; 22 раунда/строку (4 внешних +
    14 внутренних + 4 внешних); helper-столбцы `sq`/`sbox` (степень ≤3); точные `mat_external`/`mat_internal`.
    C2-пиннинг. Валидация против эталона `permute_t8`. 7 тестов. Детали — § R3.13 ниже.
- **Wide inner-hash Merkle path — t=8 path AIR** (`recursive/merkle_path_t8_air.rs`) — ✅ **готов (2026-07-13, R3.14)**
  - Аутентифицирует путь по **4-словным/124-битным узлам** через `compress_t8` — дуал
    `poseidon2_t8_air` (как `merkle_path_air` к `poseidon2_merkle_air`) и путь, который рекурсия
    воспроизводит для верификации VFRI11 FRI-layer decommitment (коллизия узла 2^15.5 → 2^62).
    Переиспользует раунд-арифметизацию t=8 (`round_schedule`/`mat_external_expr`/`mat_internal_expr`),
    цепочка из `depth` компрессий по 22 раунда; кросс-компрессионная цепочка `cur` использует тот же
    трюк смежности `out[-1]`, что и t=2 путь. 45 main + 22 preproc col; C1-привязка index/leaf/root
    (все пиннятся in-circuit, зеркально on-chain `Poseidon2MerkleVerifierT8.verify`) + C2-пиннинг.
    Reference-driven валидация + roundtrip depth 1/3/5 + rejection (wrong-root/-leaf/-index/tampered/
    forged-root/-preproc). 11 тестов. Детали — § R3.14 ниже.
- **t=16 inner hash — перестановка + compression AIR** (`poseidon2_t16.rs` + `recursive/poseidon2_t16_air.rs`)
  — ✅ **готов (2026-07-16, R3.17)**: 8-словные (248-битные) узлы → коллизия ~2^124 ≈ **128 бит**
  (ширина нативного Stwo Poseidon2-16). Детали — § R3.17 ниже.
- **t=16 Merkle path + композиция** (`merkle_path_t16_air.rs` + `composition_t16.rs`) — ✅ **готов
  (2026-07-16, R3.18)**: R2 ЗАВЕРШЁН — полный 128-битный inner-hash стек in-circuit. Детали — § R3.18

### Этап R3 — recursive verifier composition

> **Полный набор gadget'ов готов (2026-06-17):** арифметика (QM31-mul), FRI-фолд, OODS-quotient,
> inner-hash Merkle path, Fiat-Shamir transcript. R3 собирает их в единый AIR.

- **R3.1 per-query FRI step** (`recursive/query_step_air.rs`) — ✅ **готов (2026-06-17)**
  - Первый composition-gadget: в одной строке на запрос объединяет OODS± + circle fold, где
    `fPlus`/`fMinus` текут из OODS в fold **через общие trace-столбцы** (реальная data-flow, не
    отдельный proof): `OODS+: fPlus·(px−z_x)=compPos−comboPos`, `OODS−: fMinus·(−px−z_x)=compNeg−comboNeg`,
    `fold: folded=(fPlus+fMinus)+α·(fPlus−fMinus)·yInv`
  - 42 col, helper `p=(fPlus−fMinus)·yInv` держит все 16 ограничений ≤ deg 2; generic-хелпер `qmul`
    дедуплицирует раскрытие QM31-mul (×3)
  - Кросс-чек: куски шага ≡ `oods_air::comp_value_ref` (px и −px) + `fold_air::fold_ref`; roundtrip +
    2 rejection (wrong folded/compPos). 7 Rust тестов
- **R3.2 FRI fold chain** (`recursive/fri_fold_chain_air.rs`) — ✅ **готов (2026-06-17)**
  - K последовательных line-fold раундов, где вход каждого = выход предыдущего (cross-row chain):
    `output[k] = lineFold(output[k−1], sibling_k, alpha_k, xInv_k)`
  - 21 main + 1 preproc (`is_first`); C_p (deg2) + C_f (deg2) + C_chain `(1−is_first)·(input−out_prev)` (deg1);
    первая padding-строка помечается `is_first=1`, чтобы chain не ломался на границе трейса
  - Кросс-чек: single-round ≡ `fold_air::fold_ref`; 3-round chaining; roundtrip 1/4/6; 3 rejection
    (tampered/wrong-output/broken-chain). 9 Rust тестов
- **R3.3 per-query recursive verifier** (`recursive/recursive_verifier.rs`) — ✅ **готов (2026-06-17)**
  - Объединяет R3.1 (OODS± + circle fold) и R3.2 (K line-fold раундов) в **ОДИН** AIR-компонент,
    доказывающий полную per-query FRI-цепочку. Связь circleFold → lineFold₁ → … → lineFold_K
    обеспечена **cross-row constraint** (a[r]=out[r−1]), а не fingerprint-сайдченнелом
  - Унификация: оба фолда — одна формула `out=(a+b)+α·(a−b)·inv` через операнды `a`/`b`
    (row0: a=fPlus, b=fMinus; rows≥1: a=прошлый выход, b=sibling)
  - 42 main + 2 preproc (`is_step` гейтит OODS на row0, `chain_on` гейтит chain на rows 1..K);
    OODS×is_step = deg 3 (в пределах `+1` bound, как у Poseidon2-гаджетов)
  - Кросс-чек: `recursive_query_ref` ≡ `query_step_air::step_ref` (row0) + `fri_fold_chain_air::fold_chain_ref`
    (rows≥1) + `oods_air::comp_value_ref` (px/−px); roundtrip 1/4/6; rejection
    (tampered/corrupted-row0-output/corrupted-compPos/broken-chain) + **public-binding finalFold в транскрипт**
    (`mix_public(px, finalFold)`; wrong-final-value rejection). 9 Rust тестов
- **R3.4 per-query integration** (`recursive/integration.rs`) — ✅ **готов (2026-06-17)**
  - Сцепляет три sub-proof'а, верифицирующих ОДИН FRI-запрос, через общие public-значения:
    `recursive_verifier` (finalFold, QM31) → `qm31_leaf_hash` (t=2 rate-1 sponge → M31 leaf) →
    `merkle_path_air` (leaf @ idx + siblings → friLayerRoots[K])
  - `qm31_leaf_hash(v) = sponge_absorb([v≫96,v≫64,v≫32,v]).0` — рекурсивный аналог on-chain
    `Poseidon2MerkleVerifier.hashLeaf(qm31Words)` / `hash_leaf_qm31_p2`
  - Тесты: leaf-hash ≡ channel sponge; end-to-end one-query (все 3 proof'а accept + связующие
    значения совпадают); tampered-finalFold ломает цепочку (recursive proof reject + другой leaf).
    3 Rust теста
- **R3.5 multi-query aggregation** (`recursive_verifier::prove_recursive_queries`) — ✅ **готов (2026-06-17)**
  - N запросов в ОДНОМ STARK: трейс — N блоков по `1+K` строк; **AIR не меняется** — per-row
    селекторы `is_step`/`chain_on` гейтят каждый блок независимо (chain=0 на row0 каждого блока,
    поэтому запрос не «перетекает» в следующий)
  - `prove_recursive_queries(&[(StepOp, Vec<FoldRound>)])` → `(proof, log_size, Vec<finalFold>)`;
    все запросы — одинаковый `num_folds`; `mix_public_multi` привязывает все N `(px, finalFold)`
  - Рефакторинг: `fill_query_block(base, step, rounds)` переиспользуется single- и multi-путём
  - Тесты: roundtrip 5 запросов; single через multi-путь == single-путь; wrong-final одного
    запроса роняет весь proof; uneven-folds / empty — ошибки. 5 Rust тестов
- **R3.6 Fiat-Shamir draw (squeeze)** (`recursive/transcript_draw_air.rs`) — ✅ **готов (2026-06-17)**
  - Дуал к `channel_air` (absorb): доказывает цепочку Poseidon2 t=2 duplex-squeeze — ядро
    `drawSecureFelt` / `drawQueries`. Один draw из `(s0,s1)`, счётчик `d`:
    `(w0,w1)←(s0,s1)`; `s0←(s0+d)%P`; `permute`; `d++` (точно `P2Channel::draw_pair`)
  - 8 main + 7 preproc (rc0,rc1,is_init,is_first,**ndraws**,**dig0**,**dig1**): стартовый digest —
    preprocessed-константа, squeeze `(w0,w1)=cur` на init-строках, `inp0=cur0+ndraws`
  - `draw_chain(digest,m)` / `draw_secure_felt(digest)` — рекурсивные референсы; bind `(m,digest)`
  - Тесты: draw0==digest; secure-felt пакует 2 draw'а; build_trace ≡ reference; roundtrip 1/10;
    wrong-digest / wrong-count / tampered / corrupted-squeeze / zero — rejection. 11 Rust тестов.
    **87 рекурсивных Rust тестов**
- **Полный набор gadget'ов рекурсии готов (R3.6):** QM31-арифметика, FRI fold/OODS, inner-hash
  Merkle path, Fiat-Shamir absorb + draw, per-query композиция (single + N-query) + leaf-hash
  интеграция.
- **R3.8 — первая настоящая multi-gadget композиция** (`recursive/composition.rs`) — ✅ **готов (2026-06-17)**
  - `recursive_verifier` + `merkle_path` в ОДНОМ multi-component STARK (shared `TraceLocationAllocator`,
    объединённое пиннутое Tree 0 = оба preproc-набора, Tree 1 = оба main-трейса; одинаковый log_size)
  - Связующее значение привязано end-to-end: `recursive_verifier` пиннит `finalFold` (fin-столбцы +
    is_output constraint); верификатор считает `leaf = qm31_leaf_hash(finalFold)` (из пиннутого finalFold)
    и пиннит его в `merkle_path` (leaf-столбец + is_first constraint); всё Tree 0 пиннится
    `canonical_composition_preproc_root`. Prover не может (a) заявить finalFold ≠ выход fold-цепочки,
    (b) подать leaf ≠ hashLeaf(finalFold), (c) подделать селектор
  - Prerequisite: C1 leaf-binding для `merkle_path` (пиннутый leaf-столбец + `is_first·(leaf−leaf_pinned)=0`,
    `test_forged_leaf_cannot_prove`) — merkle теперь полностью C1-bound по (leaf, index)
  - `prove_query_membership(step, rounds, sibs, bits)` → `QueryMembershipResult`;
    `verify_query_membership(...)`. Тесты: roundtrip, wrong-final rejection, wrong-root rejection.
    3 Rust теста. **99 рекурсивных Rust тестов.** Mini-scale композиция (roadmap #5) перед full VFRI11
- **R3.9 — N-query композиция (VFRI11-форма)** (`composition::prove_queries_membership`) — ✅ **готов (2026-06-17)**
  - N per-query fold-цепочек + N Merkle-путей в ОДНОМ proof: N-query `recursive_verifier` +
    **multi-path `merkle`** (`build_trace_multi`/`build_preproc_multi` — N путей в одном компоненте,
    per-row `is_first` гейтит сброс каждого пути; AIR не меняется). Все finalFold_q → leaf_q → path_q
    привязаны end-to-end
  - Prerequisite: multi-path merkle (`prove_paths_multi`/`verify_paths_multi`, `test_multi_path_roundtrip`) —
    N независимых путей единой depth, пиннутый preproc (leaf/idx_bit per path)
  - `prove_queries_membership(queries, paths)` → `QueriesMembershipResult`; `verify_queries_membership(...)`.
    Тест: N=3 roundtrip + wrong-final одного запроса роняет весь proof. **101 рекурсивный тест**
- **R3.10 — FRI cherry-pick закрыт для fold-challenge (2026-06-17)** — ✅ **готов**
  - **Дизайн-realization:** дешёвый Poseidon2-канал (absorb roots → draw challenges) остаётся
    **on-chain**; challenges — public inputs рекурсивного proof'а. Значит **logup НЕ нужен** —
    достаточно пиннить challenges (как finalFold). Это понижает 1a с «нужен logup-research» до
    «механический pinning», что материально меняет production-оценку.
  - `recursive_verifier`: fold-challenge `alpha` несётся в пиннутых `alpha_p0..3` preproc-столбцах,
    ограничение `alpha − alpha_p = 0` (каждая fold-строка) заставляет trace-challenge равняться
    verifier-fixed (Fiat-Shamir-drawn) значению — prover не может cherry-pick FRI-fold-challenge
    (`test_forged_alpha_cannot_prove`). Пробрасывается через single/multi/composition (verify берёт
    `alphas`). **102 рекурсивных теста**
- **R3.11 — cherry-pick закрыт для ВСЕХ challenge-входов (2026-06-17)** — ✅ **готов**
  - Все verifier-fixed challenge-входы теперь пиннятся in-circuit: `alpha` (fold-challenge, `alpha_p`),
    `z_x` (OODS-точка, `zx_p`), `px` (query-точка, `px_p`), `inv` (twiddle, `inv_p`). `QueryChallenges`
    бандл + `query_challenges(step, rounds)`; `build_preproc` эмитит 17 preproc-столбцов; ограничения
    равенства заставляют trace использовать verifier'ские значения. Prover не может cherry-pick ни
    fold-challenge, ни OODS-точку, ни query-точку, ни twiddles
    (`test_forged_alpha_cannot_prove`, `test_forged_zx_inv_px_cannot_prove`). Пробрасывается через
    single/multi/composition. **103 рекурсивных теста. 1a полностью закрыт для per-query верификатора.**
  - Осталось до полного верификатора: (1) t=16 inner hash для 128-бит; (2) проверка root против
    committed FRI-layer корня; (3) on-chain channel-replay (absorb roots → draw challenges) в
    `QLSAVerifierRecursive.sol`, подающий challenges как public inputs
- **R3.12 — аудит: C1 root-binding закрыт для `merkle_path_air` (2026-07-10)** — ✅ **готов**
  - **[Крипто] Merkle `root` теперь пиннится in-circuit**: preproc-столбцы `is_root`/`root`
    (на last-round-строке последней РЕАЛЬНОЙ компрессии каждого пути) + ограничение
    `is_root·(s0 − root_pinned) = 0`. До этого root был привязан только через Fiat-Shamir
    `mix_public` — это исключало переиспользование честного доказательства с другим root, но
    НЕ мешало злонамеренному prover'у построить СВЕЖЕЕ доказательство для ложного root-клейма
    (siblings — свободный witness, ограничения «вычисленный корень = заявленный» не было).
    Регрессия: `test_forged_root_cannot_prove`. `depth` стал явным public input
    `verify_merkle_path` / `verify_query_membership` (фиксирует строку пиннинга root),
    зеркально on-chain `MerkleVerifier.verify(root, leaf, index, depth, siblings)`.
    Композиция single/N-query теперь value-bound end-to-end ПОЛНОСТЬЮ in-circuit:
    fin (fold output) → hashLeaf → leaf (pinned) → path → root (pinned).
  - **[Код] Капы входов** добавлены в `composition::prove/verify_query(-ies)_membership`,
    `merkle::prove/verify_paths_multi`: `MAX_QUERIES`/`MAX_NUM_FOLDS`/`MAX_DEPTH`/диапазон
    `log_size`/ёмкость трейса. Закрыты паники и OOM на враждебных входах: деление на ноль при
    `depth=0`, OOB-записи в `build_preproc` при большом `num_folds`, аллокация `2^40` при
    `log_size=40`. **104 рекурсивных теста (453 всего), сборка без предупреждений.**
  - После R3.12 остаётся: root vs *committed FRI-layer root* (on-chain интеграция), t=16
    inner hash, `QLSAVerifierRecursive.sol`.
- **R3.13 — широкий inner-hash примитив: t=8 compression AIR (2026-07-13)** — ✅ **готов**
  - `recursive/poseidon2_t8_air.rs` арифметизирует Poseidon2 **t=8** компрессию (`compress_t8`,
    4-словные/124-битные узлы → коллизия узла ~2^62) как доказуемый AIR — широкий аналог t=2
    `poseidon2_merkle_air` и та самая хеш-функция, которую рекурсия должна воспроизвести для
    верификации VFRI11-доказательства (его FRI-layer-деревья используют t=8 backend). Один раунд
    на строку (4 внешних + 14 внутренних + 4 внешних = 22, паддинг до 32); helper-столбцы
    `sq`/`sbox` держат S-box (x^5) степени ≤3; точные линейные слои `mat_external` (M_E=[[2M4,M4],[M4,2M4]])
    и `mat_internal` (J+diag(1..8)); начальный pre-mix инжектится на строке 0 через `is_first`;
    C2-пиннинг preproc (rc + is_ext/is_int/is_first) через `canonical_preproc_root`. **40 main + 11
    preproc столбцов.** Валидация: honest trace строится из уже кросс-чекнутого эталона `permute_t8`
    → неверный констрейнт роняет honest-proof, а не молча проходит (`test_round_schedule_reproduces_permutation`,
    `test_trace_node_matches_reference`, roundtrip, wrong-node/-input/corrupted/forged-preproc). **7 тестов,
    111 рекурсивных всего.** Дальше: t=8 Merkle-*path* AIR (дуал `poseidon2_t8_air`, как `merkle_path_air`
    к `poseidon2_merkle_air`), затем подключить как inner hash рекурсии, поднимая коллизию узла с
    2^15.5 (текущий t=2) до 2^62.
- **R3.14 — широкий inner-hash Merkle path: t=8 path AIR (2026-07-13)** — ✅ **готов**
  - `recursive/merkle_path_t8_air.rs` доказывает путь аутентификации по **4-словным/124-битным узлам**
    через `compress_t8` — дуал `poseidon2_t8_air` (как `merkle_path_air` к `poseidon2_merkle_air`) и
    та самая структура, которую рекурсия воспроизводит для VFRI11 FRI-layer decommitment. Ключевая
    архитектурная деталь: выход компрессии ложится на её последнюю раунд-строку, смежную с первой
    строкой следующей компрессии, поэтому кросс-компрессионная цепочка `cur` использует маску
    `out[-1]` (тот же трюк, что и t=2 путь), несмотря на 22 раунда/компрессию. **45 main + 22 preproc
    столбцов.** Раунд-ядро (in/sq/sbox/out ×8) переиспользует `round_schedule`/`mat_external_expr`/
    `mat_internal_expr` из R3.13. Node-level wiring: `cur = is_first_path·leaf + (1−is_first_path)·out_prev`,
    выбор left/right по биту индекса на 4-словных узлах, C1-привязка index (`is_first_comp·(bit−idx_bit)`),
    leaf (`is_first_path·(leaf−leaf_pin)`), root (`is_root·(out−root_pin)` на последней реальной компрессии).
    Все ограничения ≤ степень 3. C2-пиннинг preproc. Зеркально on-chain
    `Poseidon2MerkleVerifierT8.verify(root, leaf, index, depth, siblings)`. Валидация: reference-driven
    (trace из `merkle_path_root_t8`/`compress_t8`) + roundtrip depth 1/3/5 + rejection wrong-root/-leaf/
    -index/tampered + forged-root-cannot-prove (C1) + forged-preproc (C2). **11 тестов, 122 рекурсивных
    (471 всего), 0 предупреждений.** Дальше: подключить как inner hash композиции рекурсии (заменить/
    параметризовать t=2 `merkle_path_air` в `composition.rs`), затем t=16 для полных 128 бит.
- **R3.15 — широкая (t=8) композиция: recursive_verifier + merkle_path_t8 (2026-07-13)** — ✅ **готов**
  - `recursive/composition_t8.rs` доказывает `recursive_verifier` (fold-цепочка, QM31) + `merkle_path_t8`
    (4-словный путь) в ОДНОМ STARK — t=8-аналог `composition.rs`, меняющий inner hash с t=2 (узлы 31 бит,
    коллизия 2^15.5) на t=8 (4-словные узлы, 2^62), тот самый хеш, который VFRI11 FRI-layer decommitment
    реально использует. Меняется ТОЛЬКО inner-hash-гаджет; QM31 fold-цепочка и паттерн finalFold→leaf
    идентичны composition.rs. **Связка (полностью in-circuit):** `finalFold` пиннится в `recursive_verifier`
    → верификатор off-circuit считает `leaf4 = qm31_leaf_hash_t8(finalFold)` (детерминированная публичная
    функция от пиннутого finalFold; `sponge_t8` над 4 лимбами, == `hash_leaf_qm31_p2t8`) → пиннит leaf4
    в 4-словные leaf-столбцы `merkle_path_t8` → путь аутентифицирует leaf4 @ index + siblings → root.
    Value-bound end-to-end: finalFold (pinned) → hashLeaf_t8 → leaf4 (pinned) → t=8 path → root (pinned).
    87 main + 39 preproc столбцов (rv 42/17 + merkle_t8 45/22), объединённое Tree 0 пиннится (C2).
    `qm31_leaf_hash_t8` добавлен в `integration.rs`. Валидация: roundtrip + wrong-final (меняет пиннутый
    finalFold И пересчитанный leaf4) + wrong-root. **3 теста, 125 рекурсивных (474 всего), 0 предупреждений.**
    Поднимает коллизию узла inner-hash рекурсии с 2^15.5 до **2^62**. Дальше: N-query t=8 композиция
    (форма VFRI11, как R3.9 после R3.8), затем t=16 (полные 128 бит — тот же swap с t=16 path AIR).
- **R3.16 — N-query широкая композиция: форма VFRI11 на t=8 (2026-07-16)** — ✅ **готов**
  - `prove_queries_membership_t8`/`verify_queries_membership_t8` доказывают N fold-цепочек + N широких
    (4-словные узлы) Merkle-путей в ОДНОМ STARK — t=8-аналог N-query композиции R3.9. Построен на новых
    multi-path t=8 builders (`merkle_path_t8_air::build_trace_multi`/`build_preproc_multi`/
    `compute_log_size_multi`): N путей однородной глубины в последовательных блоках по `depth` компрессий
    (22 строки каждая); **AIR не меняется** — пер-строчные селекторы `is_first_path`/`is_root` гейтят
    сброс cur=leaf и пиннинг root каждого пути в своём блоке. Пер-query листья пересчитываются
    верификатором как `qm31_leaf_hash_t8(final)` и пиннятся; root каждого пути пиннится in-circuit.
    Капы входов включены сразу (урок R3.12): MAX_QUERIES/MAX_NUM_FOLDS/MAX_DEPTH/диапазон log_size/
    ёмкость трейса — враждебные входы дают Err, не панику. Тесты: 3-query roundtrip + пер-query
    rejection (wrong-final меняет пиннутый fin И leaf4; wrong-root меняет пиннутый root) +
    validation-errors. **2 теста, 127 рекурсивных (476 всего), 0 предупреждений.**
    Дальше: t=16 (полные 128 бит), root vs committed FRI-layer root (on-chain), `QLSAVerifierRecursive.sol`.
- **R3.17 — 128-битный inner hash: t=16 перестановка + compression AIR (2026-07-16)** — ✅ **готов**
  - `poseidon2_t16.rs`: Poseidon2 t=16 над M31 — ФИНАЛЬНАЯ ступень лестницы (t=2→t=4→t=8→**t=16**).
    R_F=8 (4+4), R_P=14, α=5 (Poseidon2 Table 1 для 31-битных полей, t=16); M_E = circ(2·M4,M4,M4,M4)
    (§5.1 block construction, M4 переиспользуется из t=8); M_I = J+diag(1..16) (обратимость доказана
    Гауссом в тесте); RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t16" ‖ i_be4)[..4]) mod P, i∈0..142.
    Rate-8/capacity-8 губка (odd-length флаг в capacity-ячейке 15) + 2-to-1 компрессия по
    **8-словным (248-битным) узлам → коллизия ~2^124 ≈ 128 бит** — целевой уровень, ширина нативного
    Stwo Poseidon2-16. Frozen reference-векторы. 6 тестов.
  - `recursive/poseidon2_t16_air.rs`: арифметизация `compress_t16` — 80 main + 19 preproc столбцов,
    та же схема один-раунд-на-строку (22 раунда) + helper-столбцы `sq`/`sbox` (степень ≤3), что у t=8;
    обобщённые 16-ячеечные `mat_external16_expr`/`mat_internal16_expr` кросс-чекнуты против
    референс-слоёв отдельным тестом; C2-пиннинг preproc. Валидация: expr-слои ≡ референс,
    round-schedule ≡ permute_t16, trace node ≡ compress_t16, roundtrip, wrong-node/-input,
    corrupted-trace, forged-preproc. 7 тестов. **134 рекурсивных (489 всего), 0 предупреждений.**
  - Дальше: t=16 Merkle-path AIR + композиция (тот же swap, что R3.14/R3.15) → полный 128-битный
    inner-hash стек; затем on-chain интеграция (root vs committed FRI-layer root,
    `QLSAVerifierRecursive.sol`).
- **R3.18 — 128-битный inner-hash стек ЗАВЕРШЁН: t=16 path AIR + composition_t16 (2026-07-16)** — ✅ **готов**
  - `recursive/merkle_path_t16_air.rs`: путь аутентификации по **8-словным (248-битным) узлам** через
    `compress_t16` — дуал `poseidon2_t16_air`, тот же механический swap, что R3.14 (t=8). 89 main + 38
    preproc столбцов; переиспользует раунд-арифметизацию t=16 (`round_schedule`/`mat_external16_expr`/
    `mat_internal16_expr`); кросс-компрессионная цепочка `cur` — тот же трюк смежности `out[-1]`;
    C1-привязка index/leaf/root in-circuit + C2-пиннинг; multi-path builders (`build_trace_multi`/
    `build_preproc_multi`) включены сразу. 11 тестов (reference-driven + roundtrip depth 1/3/5 +
    rejection + forged-root/-preproc).
  - `recursive/composition_t16.rs`: `recursive_verifier` + `merkle_path_t16` в ОДНОМ STARK — single- И
    N-query (форма VFRI11), t=16-аналог composition_t8. Связка `leaf8 = qm31_leaf_hash_t16(finalFold)`
    (rate-8 губка над 4 лимбами, `integration.rs`) пиннится в 8-словные leaf-столбцы. Value-bound
    end-to-end полностью in-circuit на **~2^124 ≈ 128-битной коллизии узла**: finalFold (pinned) →
    hashLeaf_t16 → leaf8 (pinned) → t=16 путь → root (pinned). Капы входов с самого начала. 5 тестов
    (roundtrip + wrong-final/-root + N-query roundtrip с пер-query rejection + validation-errors).
  - **Лестница inner-hash (t=2 → t=8 → t=16) ЗАВЕРШЕНА in-circuit** — каждая ступень была чистым
    swap'ом hash-backend'а при неизменном паттерне композиции (сработало с первого прогона все три
    раза — R3.15, R3.16, R3.18). **150 рекурсивных тестов (505 всего), 0 предупреждений.**
  - Дальше: on-chain интеграция — root vs committed FRI-layer root, channel-replay,
    `QLSAVerifierRecursive.sol` + `BatchRegistryV7`.
- **R4.1 — рекурсия верифицирует РЕАЛЬНЫЙ VFRI11-конвейер: root vs committed FRI-layer root (2026-07-16)** — ✅ **готов**
  - Рефакторинг (чистый code-motion): FRI-цепочка `gen_vfri11_hints_from_cols_nfolds` вынесена в общий
    helper `vfri11_fri_chain` (транскрипт t=8-канала, OODS, comp-дерево, fold-слои, деревья слоёв,
    derived indices) — ABI-генератор и новый мост потребляют ОДНУ реализацию и не могут разойтись
    по построению. Существующие VFRI11-тесты (smoke/deterministic/differs) зелёные без изменений.
  - **`gen_vfri11_recursion_inputs`** (vfri2_bridge.rs): извлекает из реального конвейера per-query
    входы рекурсии — `StepOp` (f±, px, z_x, combos, friAlpha, y⁻¹), fold-раунды (sibling, channel-alpha,
    index-ориентированный twiddle⁻¹) и Merkle-путь финального фолда в **committed** last-layer дерево.
    Тонкость ориентации: `line_fold(sib, cur)` при cur в верхней половине = тот же фолд с ОТРИЦАННЫМ
    twiddle⁻¹ ((b−a)·inv = (a−b)·(P−inv)) — знак детерминирован битом индекса (публичные данные).
    Жёсткий инвариант (не debug-only): извлечённая цепочка обязана воспроизвести committed-значение
    последнего слоя, иначе Err — любая ошибка ориентации/извлечения ловится немедленно.
  - **E2E-тесты:** (1) мост + `prove_queries_membership_t8` над реальными данными → `verify == true`,
    `finals == реальные fold-выходы`, каждый путь аутентифицируется в ПОДЛИННЫЙ `friLayerRoots[K]`;
    трейс-корень моста == `proof[8..40]` ABI-генератора (общая цепочка); tamper root → reject.
    (2) orientation-coverage: depth 5 × 3 фолда × 6 запросов — обе ориентации fold-раундов.
    **«root vs committed FRI-layer root» закрыт на Rust-уровне. 507 тестов (150 рекурсивных),
    0 предупреждений.**
  - Дальше: on-chain channel-replay (absorb roots → draw challenges/indices, сверка с public inputs
    рекурсивного proof) + `QLSAVerifierRecursive.sol` + `BatchRegistryV7`.
- `recursive/recursive_bridge.rs` — `prove_vfri11_recursive(inner_proof, hints)` + PyO3
- Двухфазная стратегия: (A) recursive proof для LOG=10 группы; (B) мета-схема объединяет LOG=10+LOG=8

### R3.7 — блокеры soundness: C1/C2 ЗАКРЫТЫ для `recursive_verifier` (2026-06-17)

Аудит (крипто + код) выявил два composition-level пробела против злонамеренного prover'а. **Оба
теперь закрыты для флагманского composition-гаджета `recursive_verifier`** (single + N-query):

- **[C1 — ИСПРАВЛЕНО] Привязка выхода.** Verifier-fixed заявленный final несётся в пиннутых
  preprocessed-столбцах `fin0..fin3`, а in-circuit ограничение `is_output·(out − fin)=0` заставляет
  реальную выходную строку трейса равняться ему. Prover, чей трейс вычислил X, не может заявить Y≠X
  (regression `test_forged_output_cannot_prove` — prove падает на нарушении ограничения).
- **[C2 — ИСПРАВЛЕНО] Пиннинг preprocessed.** Селекторы + столбцы заявленного выхода производит единый
  канонический источник `build_preproc`; верификатор пересчитывает их commitment-корень через
  `canonical_preproc_root` (`CommitmentSchemeProver::roots()`) и отклоняет proof, чей `commitments[0]`
  отличается — forged `is_step≡0` больше не верифицируется (regression `test_forged_selector_rejected`;
  раньше → `verify=true`). 90 рекурсивных тестов.

**C2-пиннинг портирован на ВСЕ standalone sub-гаджеты (2026-06-17):** `merkle_path_air`, `channel_air`,
`transcript_draw_air`, `fri_fold_chain_air` — у каждого witness-free `build_preproc(...)` (единый
канонический источник round-констант / селекторов / счётчиков / digest) + пиннинг корня в `verify_*`;
forged preprocessed-дерево больше не верифицируется (regression `test_forged_preproc_rejected` в каждом).
`verify_fold_chain`/draw/merkle принимают структурные public-параметры (`num_rounds`/`(m,digest)`/`log_size`)
для реконструкции канонического дерева. **94 рекурсивных теста.**

**C2-пиннинг портирован на production V23-конвейер (2026-06-17):** все 5 зрелых верификаторов в
`stark_stwo/src/lib.rs`, несущих preprocessed-столбец `is_init_uh` — `verify_use_hint_batch_v2`,
`verify_norm_use_hint_combined`, `verify_az_ct1_norm_use_hint_combined`, `verify_full_mldsa_witness_combined`
(V21/V22), `verify_full_mldsa_witness_v23` — пиннят preprocessed-корень через `canonical_uh_preproc_root(max_log)`
(зеркалит config каждого prover'а; `build_preproc_v2` — единый источник). Forged `is_init_uh≡0` (ослабил бы
сброс hint-weight-аккумулятора на row 0 → мог обойти границу OMEGA=55) больше не верифицируется
(`test_use_hint_batch_v2_forged_preproc_rejected`); honest V21/V22/V23 roundtrip'ы проходят
(`test_prove_verify_mldsa_v2{1,2,3}_roundtrip`) + combined roundtrip.

**C2 закрыт для ВСЕХ preprocessed-верификаторов репозитория (2026-06-17):** + Poseidon2 hash-chain
верификатор `verify_hash_chain_poseidon2` (`poseidon2_air::build_preprocessed` + `canonical_hashchain_preproc_root`,
log_size-параметризован). Ни один верификатор больше не принимает непиннутое Tree 0. 443 быстрых Rust-теста
зелёные (+`test_hash_chain_preproc_pin`, +`test_use_hint_batch_v2_forged_preproc_rejected`, honest V21/V22/V23).

**C1 index-binding закрыт для `merkle_path_air` (2026-06-17):** claimed `index` привязан in-circuit —
пиннутый preproc-столбец `idx_bit` несёт бит индекса на compression, ограничение `is_init·(bit − idx_bit)=0`
заставляет trace-биты пути равняться ему; заявленный `index`, расходящийся с committed-путём, недоказуем
(`test_forged_index_bits_cannot_prove`). Закрывает Medium-находку код-аудита («index не привязан к trace bits»).

**Остаётся (R3.7 follow-up):** C1 output-binding (`root`/`finalFold`) реализован в `recursive_verifier`
(finalFold) и `merkle_path_air` (index); остальные public-выходы sub-гаджетов и lib.rs-верификаторов
привязаны через Fiat-Shamir (для V23 выход — fingerprint в канал; для merkle `root`/`leaf` — ужесточается
на композиции, где leaf = пиннутый per-query fold-выход, root = committed FRI-layer корень). `recursive_verifier`
/ `canonical_uh_preproc_root` — референс.

Исправлено в этом аудите (robustness): input-cap'ы `MAX_QUERIES`/`MAX_NUM_FOLDS` (до size-multiply),
guard пустого `build_trace_multi`, `bits_to_index` assert для depth>32, brittle tamper-тест
(`is_err()`→`!verify().unwrap_or(false)`).

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
