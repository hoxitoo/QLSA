# QLSA — Project Context

## R4.8 (2026-07-30) — газовый барьер снят: полная on-chain верификация в ОДНОЙ транзакции

**Все зафиксированные ранее «газовые стены» оказались накладными расходами реализации Poseidon2
в Solidity, а не свойством протокола.** Rust не менялся; каждый хеш побитово тот же.

**Две ошибки измерения, из-за которых стены выглядели непреодолимыми:**
1. `gasLimit` > 2^24 **не исполняется** — hardhat (и mainnet после EIP-7825) отклоняет транзакцию
   ДО исполнения с `transaction gas limit (X) is greater than the cap (16777216)`. Вывод R4.6
   «полный путь превышает даже 29M» опирался на такой вызов: honest path ни разу не был доведён
   до конца, а сообщение об отказе было принято за out-of-gas.
2. `estimateGas` **завышает** транзакции с вложенными вызовами (правило 63/64 на каждый кадр):
   для `submitBatch` с VFRI11 оценка = 18 174 156 при фактическом `gasUsed` = 6 058 052.
   **Мерить надо `gasUsed` реально отправленной транзакции.**

**Настоящая причина стоимости:** одна t=8 перестановка стоила ~106k газа, тогда как её арифметика
(~350 `mulmod` + ~700 сложений) ≈ 3k. Остальные ~97% — `uint256[8] memory` (аллокация +
MLOAD/MSTORE на каждую ячейку каждого раунда) и условное вычитание `if (r >= P) r -= P` на КАЖДОМ
сложении линейного слоя.

**Исправление** (`Poseidon2M31T8.sol`, `Poseidon2M31T4.sol`, + `Poseidon2ChannelT8`/
`Poseidon2MerkleVerifierT8` на новые точки входа):
- **состояние на стеке**: `permute8(s0..s7)`, `compress4`, `sponge4`, `_permuteInto` — без
  `uint256[8] memory`;
- **ленивая редукция**: линейные слои складывают БЕЗ `mod P`. Это точно, а не приближённо:
  сложение/умножение mod P — гомоморфизмы кольца, а каждый S-box идёт через `mulmod(…, P)`, который
  редуцирует свой выход при любом размере входа. Редукция нужна только на выходе перестановки.
  Оценка величин: пик ≈2^80 (t=8) и ≈2^99 (t=4) — далеко до 2^256.

Корректность: **47 существующих кросс-чек-тестов против ЗАМОРОЖЕННЫХ Rust-референс-векторов
проходят без изменений** (`poseidon2_t4.rs`/`poseidon2_t8.rs`/`vfri2_bridge.rs`) — все хеши,
Merkle-корни и Fiat-Shamir-транскрипты идентичны. Полный набор контрактов: **1015 passing, 0 failing**
(и весь прогон ускорился с ~11 мин до ~1 мин).

**Измерено (фактический `gasUsed` / исполненный `staticCall`):**

| Путь | До | После |
|------|-----|-------|
| `t8.permute` / `t4.permute` (harness) | 127 228 / 61 331 | **36 251 / ~16 000** |
| `replayChallenges` (t=8 канал) | 6 059 429 | **733 849** |
| `VFRI11.verify` (внешний recursive proof) | 11 296 675 | **1 545 728** |
| **`verifyRecursive` (весь honest path)** | не исполнялся | **2 289 889, `ok = true`** |
| VFRI10 (t=4) V23 LOG=10 / LOG=8 | ~10.6M / ~7.9M | **2 065 966 / 1 588 923** |
| **VFRI10 dual `submitBatch`** | ~18.5M (> cap → 2 tx) | **3 736 943 — одна tx** |
| VFRI11 (t=8) V23 LOG=10 / LOG=8 | **>100M** | **3 342 623 / 2 633 375** |
| **VFRI11 (t=8) dual `submitBatch`** | не верифицировался | **6 058 052 — одна tx** |
| BatchRegistryV6 per-group (t=4) | ~10.6M / ~7.9M | **2 147 099 / 1 701 231** |

**Следствия:**
1. **t=8 (стойкость узла ~2^62) теперь развёртываем в одной транзакции** — апгрейд относительно
   текущего production t=4 (~2^31), а не только ускорение.
2. **Двухтранзакционный split `BatchRegistryV6` больше не обязателен**: `BatchRegistryV5` с единым
   `submitBatch` укладывается в cap и для t=4 (3.7M), и для t=8 (6.1M). V6 остаётся валидным при
   желании снизить пик газа на транзакцию.
3. **On-chain контур рекурсии закрыт** при t=8 с ~7× запасом под cap. Рекурсия остаётся целью для
   (а) 128-бит через t=16 как inner hash и (б) КОНСТАНТНОЙ стоимости независимо от размера батча —
   ширина перестановки этого не даёт.

Обновлены тесты, кодировавшие устаревшие стены: `QLSAVerifierVFRI10CrossBoundE2E` (dual submit теперь
обязан ФИНАЛИЗИРОВАТЬСЯ в одной tx), `QLSAVerifierVFRI11CrossBoundE2E` (обе t=8 группы обязаны
`verify()==true`, + dual submit в одной tx), `QLSAVerifierRecursive` (honest bundle обязан
`ok==true`). Подробности: `docs/roadmap/recursion.md` § R4.8.

### MVP-7 — стек t=8 в одной транзакции (2026-07-30)

Апгрейд, который стал возможен после R4.8: `--stack v7` = `QLSAVerifierVFRI11` (Poseidon2 t=8,
4-словные/124-бит узлы → стойкость узла ~2^62) + `BatchRegistryV5` (атомарная двойная проверка в
ОДНОЙ транзакции). Против текущего production `--stack v6` (t=4, ~2^31, split на 2 tx).

- `contracts/scripts/deploy_v7.js` + `testnet/deploy_v7.sh` — деплой VFRI11 + BatchRegistryV5
- `testnet.submit.OnchainSubmitterV5` — подкласс `OnchainSubmitterV4` (ABI BatchRegistryV4 и V5
  побитово идентичны, различается только подключённый верификатор); один `submit_batch_with_nonces()`
- `python -m testnet.e2e --stack v7` — `prove_mldsa_sig_vfri11_stark`, `num_folds=6`
- **Полный цикл проверен на свежем доказательстве**: подпись ML-DSA-65 → V23 → VFRI11 cross-bound →
  `submitBatchWithNonces` на развёрнутом `BatchRegistryV5` → finalized, **6 150 487 газа в одной
  транзакции**, с проверкой nonce'ов

**[БАГ НАЙДЕН И ИСПРАВЛЕН] Отображение nonce'ов в testnet-обвязке.** Проверка полного цикла на
свежем доказательстве вскрыла давний дефект: on-chain реестры (`BatchRegistryV4`/`V5`/`V6`) хранят 0
для ни разу не виденного отправителя и требуют `newNonce > stored`, то есть минимальный отправляемый
nonce равен 1. А `testnet/e2e.py` передавал 0-based `tx.nonce` без сдвига — поэтому ЛЮБАЯ реальная
(не `--dry-run`) отправка падала с `SenderNonceTooLow(provided=0, expected=1)` на отправителе tx[0],
во всех трёх стеках (v4, v6, v7). Баг был достижим только при настоящей отправке, поэтому
`--dry-run` его никогда не показывал. Исправлено в единственной точке стыка соглашений:
`testnet.e2e.build_sender_nonces()` отображает `tx.nonce → nonce+1`, сохраняя строгую монотонность;
7 регрессионных тестов в `tests/test_testnet_nonces.py`.

Инфраструктура: `contracts/hardhat.config.js` получил опциональный обход загрузки компилятора для
песочниц с закрытым egress — `QLSA_LOCAL_SOLCJS=1` использует `soljson.js` из npm-пакета `solc`
(тот же компилятор, медленнее). Без переменной поведение не меняется, CI не затронут.

## Аудит R4.2–R4.7 (2026-07-26) — привязаны ВСЕ публичные поля inner-statement

Двухэкспертный аудит (крипто + код) on-chain слоя рекурсии. Одна HIGH-находка каждого типа,
обе исправлены.

- **[КРИПТО HIGH — ИСПРАВЛЕНО] `verifyRecursive` связывал лишь 2 из 8 полей `InnerPublics`.**
  `bound = keccak(traceRoot ‖ lastLayerRoot)` оставлял вне привязки `oodsComboPos/Neg`, `compRoot`,
  внутренние `friLayerRoots`, `batchRoot`, `treeDepth`, `nQueries`: злоумышленник мог переиспользовать
  валидный внешний proof, подменив эти поля, и всё равно получить `ok=true` — а возвращаемые
  challenges (посчитанные уже по подменённым значениям) нигде не сверялись. Исправлено: в binding-root
  хешируются ВСЕ публичные поля, одна раскладка зеркально на обеих сторонах:
  `traceRoot(32) ‖ oodsPos(16) ‖ oodsNeg(16) ‖ compRoot(32) ‖ nRoots(4) ‖ root_i(32)* ‖ batchRoot(32)
  ‖ treeDepth(4) ‖ nQueries(4)`. Rust: общий `outer_binding_root(&Vfri11ChannelInputs)` (одна
  реализация для теста R4.4 и генератора фикстуры). Solidity: `outerBindingRoot(InnerPublics)`.
  Регрессия: binding обязан меняться при изменении ЛЮБОГО из семи ранее непривязанных полей.
- **[КРИПТО MEDIUM — ИСПРАВЛЕНО]** в channel-replay не было капа `MAX_FOLD_ROUNDS`, который есть в
  VFRI11 → добавлен `≤29` корней в Solidity-библиотеке и в `vfri11_replay_channel`.
- **[КРИПТО LOW — ИСПРАВЛЕНО]** `build_trace_multi_raw` паниковали на превышении ёмкости при прямом
  вызове → сужены до `pub(crate)`, единственный вызывающий — валидирующий `outer_trace_columns_t8`.
- **[КОД HIGH — ИСПРАВЛЕНО]** NatSpec `QLSAVerifierRecursive` всё ещё утверждал, что сжатая
  конфигурация «внутри газового профиля», хотя следующий же замер показал превышение 29M: тест и
  roadmap я тогда обновил, а доккомментарий контракта — нет. Переписан на измеренный факт + что
  реально верифицируется on-chain + два пути решения.
- **[КОД LOW ×2, INFO ×1 — ИСПРАВЛЕНО]** убраны три избыточных copy-loop для `friLayerRoots`
  (параметр библиотеки теперь `calldata`); тавтологический `expect(true)` заменён реальной проверкой;
  фикстура E2E дополнена `compAlpha`/`friAlpha`/`friAlphas` + утверждения в тесте.
- **Чистые зоны (подтверждено обоими):** порядок операций Fiat-Shamir Rust↔Solidity бит-в-бит
  (включая MSB-first `qm31Words`, диапазоны байт `mixRootW`=[16..32] / `mixRootFull`=все 32);
  сплит `build_trace_multi_raw` — чистое code-motion; кавычки uint128 в фикстурах не регрессировали;
  секретов и утечек в сообщениях об ошибках нет; `outer_trace_columns_t8` валидирует входы наравне с
  prove-путём.
- **Итог: 516 Rust-тестов, 0 предупреждений; контракты компилируются чисто (viaIR); CI зелёный.**

## Рекурсия R4.5 (2026-07-18) — QLSAVerifierRecursive.sol: on-chain вход рекурсии (MVP)

Сборка обеих on-chain половин рекурсии в один контракт. `verifyRecursive(inner, outerProof,
outerCommitment, outerHints) → (ok, challenges)`:
1. **Replay внутреннего канала** (R4.3) из публичных корней inner-proof → challenges/query-indices
   возвращаются вызывающему — верхние слои потребляют channel-derived, а не prover-chosen значения.
2. **Binding-root** = `keccak(innerTraceRoot ‖ низкие 16 байт lastLayerRoot)` — побайтово == Rust
   R4.4 (4 BE-слова wide-узла t=8).
3. **Верификация внешнего proof** задеплоенным `QLSAVerifierVFRI11` под этим binding-root — по
   дизайну; НО (обнаружено в CI) внешний трейс имеет tree_depth ≥ 6 (t=8-компрессии merkle-путей
   доминируют), что выходит за газовый профиль VFRI11 (валидирован на depth 4) → полная on-chain
   verifyRecursive ревертит на этой глубине.

- **Модель доверия (честно):** внешняя верификация — VFRI-частичная (FRI low-degree + FS + Merkle
  binding), как у production BatchRegistryV6; AIR-ограничения рекурсии + C1/C2-пиннинг — Rust-сторона.
- **On-chain подтверждено (Solidity-тесты):** `replayChallenges(inner)` → challenges/indices ==
  Rust-replay (byte-identical), сдвиг при tamper inner publics, revert на out-of-range;
  `outerBindingRoot` == Rust keccak-биндинг. Полная verify внешнего proof — off-chain (Rust
  `test_recursive_outer_trace_vfri11_hints`), помечена pending в контракте (VFRI11 gas/tree-depth).
- Контракт компилируется чисто (solc-js viaIR, 0 предупреждений; EVM-прогон — CI Solidity-джоб).
  **517 Rust-тестов, 0 предупреждений.**
- **Дальше:** gas-appropriate outer-верификатор (per-fold split, как BatchRegistryV6, либо меньший
  внешний трейс) → полная on-chain verifyRecursive; `BatchRegistryV7`; PyO3/SDK.
  `docs/roadmap/recursion.md` § R4.5.

## Рекурсия R4.4 (2026-07-18) — внешний трейс рекурсии → существующая VFRI11-машинерия

Ключевой архитектурный шаг к `QLSAVerifierRecursive.sol`: внешний рекурсивный трейс мал (87 столбцов,
сотни строк) → его можно верифицировать on-chain УЖЕ ЗАДЕПЛОЕННОЙ VFRI11-машинерией за малый
константный газ, не пиша новый полный Stwo-верификатор в Solidity.

- **Сплит билдеров (code motion):** `rv::build_trace_multi_raw` + `merkle_path_t8_air::build_trace_multi_raw`
  выдают натуральный порядок (до bit-reverse), обёртки зовут raw + финализацию — единая реализация.
  `composition_t8::outer_trace_columns_t8(queries, paths) → (87 колонок u32, log_size)` с той же
  валидацией, что prove_queries_membership_t8.
- **Кросс-привязка:** `outer batch_root = keccak(inner trace_root ‖ inner last_layer_root)`
  (паттерн BatchRegistryV4). VFRI11-канал миксует batch_root перед drawQueries → внешние хинты
  специфичны внутренним корням; тест подтверждает (другой root → другие хинты).
- **Тест** `test_recursive_outer_trace_vfri11_hints`: реальные R4.1 recursion-inputs → внешний трейс →
  `gen_vfri11_hints_from_cols_nfolds` без изменений → VFRI11-proof (маркер версии 5), детерминизм,
  binding. **516 тестов, 0 предупреждений.**
- **Семантика (честно):** VFRI-частичная верификация внешнего трейса — та же модель доверия, что у
  production BatchRegistryV6 сегодня; полный on-chain AIR-check остаётся документированным
  ограничением VFRI-линейки (снимается в будущем полной заменой или SNARK-обёрткой).
- **Дальше:** `QLSAVerifierRecursive.sol` = RecursiveChannelReplay (R4.3, CI green) +
  VFRI11.verify(outer) + сверка replay-challenges с пиннутыми public inputs; `BatchRegistryV7`; E2E.
  `docs/roadmap/recursion.md` § R4.4.

## Рекурсия R4.3 (2026-07-16) — on-chain channel-replay в Solidity

Первый Solidity-кирпич `QLSAVerifierRecursive.sol`. `contracts/src/verifier/RecursiveChannelReplay.sol`
— зеркало Rust `vfri11_replay_channel` (R4.2) на уже бит-в-бит кросс-чекнутом `Poseidon2ChannelT8`:
из публичных committed-корней (traceRoot, oods_combo_pos/neg, compRoot, friLayerRoots[0..=K], batchRoot,
treeDepth, nQueries) без трейса/witness выдаёт `Challenges{zX, compAlpha, friAlpha, friAlphas[],
queryIndices[]}` — те public inputs, к которым привязан рекурсивный proof (решение R3.10: challenges
как public inputs, канал on-chain). Op-order (mixRootFull(traceRoot)→drawSecureFelt×2→mixU32s(8 combo
слов)→mixRootW(compRoot)→drawSecureFelt→mixRootW(layer0)→loop[drawSecureFelt+mixRootW]→mixRootFull(batch)
→drawQueries) байт-в-байт == Rust. `qm31Words` MSB-first, guard'ы treeDepth∈[2,30]/nQueries∈[1,64]/≥1 root.
Кросс-чек: Rust-фикстура `vfri11_channel_replay.json` + `RecursiveChannelReplay.test.js` (harness):
on-chain replay == Rust draws, tamper traceRoot сдвигает challenges, revert на out-of-range.
Контракт компилируется чисто (solc-js viaIR, 0 предупреждений; solc 0.8.35 в CI — egress-политика
блокирует локальную загрузку компилятора, EVM-тест гоняется в Solidity-джобе CI). **515 Rust-тестов
(+1 fixture-writer), 0 предупреждений.** Дальше: `QLSAVerifierRecursive.sol` + `BatchRegistryV7` + E2E.
`docs/roadmap/recursion.md` § R4.3.

## Рекурсия R4.2 (2026-07-16) — on-chain channel-replay эталон

Начало Solidity-фазы с Rust-эталона (крит.-замечание №5: сперва валидация на Rust).
`vfri11_replay_channel(Vfri11ChannelInputs) -> Vfri11ChannelChallenges` в vfri2_bridge.rs: из ОДНИХ
публичных committed-корней (trace_root, oods_combo_pos/neg, comp_root, friLayerRoots[0..=K], batch_root,
tree_depth, n_queries) — без трейса/witness — реплеит Poseidon2 t=8 канал и выдаёт ровно те
challenges/indices (`z_x`, `comp_alpha`, `fri_alpha`, per-fold `fri_alphas`, query-индексы), к которым
привязан рекурсивный proof (по решению R3.10 challenges — public inputs, канал остаётся on-chain).
Порядок операций байт-в-байт == `vfri11_fri_chain`. Тест `test_vfri11_channel_replay_matches_chain`:
replay из корней реальной цепочки совпадает с её draws; tamper trace_root сдвигает z_x + индексы
(нельзя cherry-pick запросы подменой корня). Это точная спецификация для `QLSAVerifierRecursive.sol`
(Poseidon2ChannelT8 уже кросс-чекнут). **514 тестов, 0 предупреждений.** Дальше: контракт + BatchRegistryV7
+ PyO3/SDK + E2E. `docs/roadmap/recursion.md` § R4.2.

## Аудит (2026-07-16) — C1 input/output binding закрыт в compression-AIR (R3.13–R4.1)

Двухчастный аудит (крипто + код) свежей поверхности R3.13–R4.1 (t=8/t=16 inner-hash стек ~5500 строк
+ VFRI11-мост рекурсии). Два эксперта-агента + инлайн-верификация. **Одна HIGH-находка исправлена**,
остальное — LOW/MEDIUM-гигиена, всё закрыто.

- **[HIGH, крипто — ИСПРАВЛЕНО] Пиннинг входа/выхода в standalone compression-гаджетах.**
  `poseidon2_t8_air`/`poseidon2_t16_air`: `prove_compress`/`verify_compress` привязывали заявленный
  триплет `(left,right,node)` к трейсу только через Fiat-Shamir `mix_public` — злонамеренный prover
  мог доказать ЛОЖНОЕ `compress(FAKE_left, FAKE_right) = node` (тот же класс, что закрытый в R3.12
  root-binding). **Не достижимо в production** (эти функции вызываются только из своих
  `#[cfg(test)]`-модулей; композиция использует merkle-path AIR, где пиннинг уже был), но это была
  латентная ловушка в публичном API, нарушавшая инвариант репо «ни один verify_* не принимает
  непиннутую привязку». Фикс по паттерну R3.12: preproc-столбцы `raw_pin[0..T]` (is_first-gated) +
  `node_pin[0..T/2]` (is_node-gated) + in-circuit равенства; `canonical_preproc_root`/`verify_compress`
  строят их из переданных верификатором `(left,right,node)`. Регрессии `test_forged_input_cannot_prove`
  в обоих файлах.
- **[MEDIUM, код — ИСПРАВЛЕНО] Пробел в тестах t16 vs t8-шаблон.** Добавлены
  `test_external_matrix_invertible` + naive-cross-check линейных слоёв (16×16 эталон с нуля) +
  `test_rc_count_and_range` в `poseidon2_t16.rs` — независимо подтверждают, что M_E = circ(2·M4,…) и
  M_I = J+diag(1..16) суть именно те матрицы.
- **[LOW, код — ИСПРАВЛЕНО]** stale Vec-capacity `leaves.len()*9 → *17` в composition_t16; устаревшие
  "t=8" doc-комментарии, intra-doc-ссылки и runtime `format!`-строки ошибок внутри t16-файлов →
  t16/8-word/M31⁸; stale "32 main columns" в poseidon2_t8_air → 40.
- **Чистые зоны (подтверждено обоими агентами + инлайн):** C1/C2 в merkle-path t8/t16 (index/leaf/root
  пиннятся, canonical-root сверяется в обоих verify-путях); связка композиции finalFold→leaf→root
  пиннутая end-to-end; ориентационный трюк R4.1 корректен (тождество проверено, жёсткий инвариант
  ловит ошибки); рефакторинг vfri11_fri_chain — byte-for-byte behavior-preserving (фикстура
  идентична); ширина узла (t8 124-бит / t16 248-бит) течёт без усечения; M_I обратима (det≠0);
  секретов нет; входные капы в публичных entry-points на месте.
- **Итог: 513 тестов (+6), 152 рекурсивных, 0 предупреждений. Находок soundness в production-пути нет.**

## Рекурсия R4.1 (2026-07-16) — рекурсия верифицирует РЕАЛЬНЫЙ VFRI11-конвейер

Старт финальной фазы (R4, on-chain интеграция) с её первого пункта: **«root vs committed FRI-layer
root» закрыт на Rust-уровне** — рекурсивная композиция доказывает per-query decommitments настоящего
VFRI11-конвейера против подлинного committed-корня последнего FRI-слоя (не синтетических данных).
Это же закрывает критическое замечание роадмапа №5 (bootstrapping: сперва рекурсия мини-proof на
реальных данных).

- **Рефакторинг без изменения поведения:** FRI-цепочка `gen_vfri11_hints_from_cols_nfolds`
  (транскрипт t=8-канала: mix trace root → z_x → comp_alpha → combos → comp root → friAlpha →
  fold-слои → batch root → draw indices) вынесена в общий helper `vfri11_fri_chain` — ABI-генератор
  и мост рекурсии потребляют ОДНУ реализацию, дрейф невозможен по построению. Существующие
  VFRI11-тесты зелёные без правок.
- **`gen_vfri11_recursion_inputs`** извлекает per-query входы рекурсии: `StepOp` (f± из OODS-квотиентов,
  px, z_x, combos, friAlpha, y⁻¹), fold-раунды (sibling из слоя k, channel-alpha_k,
  index-ориентированный twiddle⁻¹), путь финального фолда в committed last-layer дерево (4-словные
  t=8 узлы), `last_layer_root`, `trace_root`. **Тонкость ориентации:** VFRI кладёт cur в
  (gp,gm)=(sib,cur) при cur_idx ≥ layer_sz; рекурсия всегда цепляет cur как операнд `a` — свап
  эквивалентен отрицанию twiddle⁻¹ ((b−a)·inv = (a−b)·(P−inv)), знак детерминирован битом индекса.
  **Жёсткий инвариант** (не debug-only): извлечённая цепочка обязана воспроизвести committed-значение
  последнего слоя, иначе Err.
- **E2E-тесты (2):** мост → `prove_queries_membership_t8` → `verify == true` над реальными данными;
  `finals` == реальные fold-выходы; каждый путь аутентифицируется в подлинный `friLayerRoots[K]`;
  `trace_root` моста == `proof[8..40]` ABI-генератора (доказательство общей цепочки); tamper root →
  reject. Плюс orientation-coverage (depth 5 × 3 фолда × 6 запросов — обе ориентации).
  **507 тестов (150 рекурсивных), 0 предупреждений.**
- **Дальше:** on-chain channel-replay (дешёвый Poseidon2-канал absorb roots → draw challenges/indices,
  сверка с public inputs рекурсивного proof) → `QLSAVerifierRecursive.sol` + `BatchRegistryV7`.
  `docs/roadmap/recursion.md` § R4.1.

## Рекурсия R3.18 (2026-07-16) — 128-битный inner-hash стек ЗАВЕРШЁН (t=16 path + композиция)

Завершение лестницы inner-hash: t=16 Merkle-path AIR + композиция — тот же механический swap, что
R3.14/R3.15 (t=8), на **8-словных (248-битных) узлах → коллизия ~2^124 ≈ 128 бит** (целевой уровень).

- **`recursive/merkle_path_t16_air.rs`** (11 тестов): путь аутентификации через `compress_t16`,
  дуал `poseidon2_t16_air`. 89 main + 38 preproc столбцов; раунд-ядро переиспользует
  `round_schedule`/`mat_external16_expr`/`mat_internal16_expr` из R3.17; кросс-компрессионная
  цепочка `cur` — трюк смежности `out[-1]` (22 раунда/компрессия); C1-привязка index/leaf/root
  in-circuit + C2-пиннинг preproc; multi-path builders включены сразу (для N-query).
- **`recursive/composition_t16.rs`** (5 тестов): `recursive_verifier` + `merkle_path_t16` в ОДНОМ
  STARK, single- И N-query (форма VFRI11). Связка `leaf8 = qm31_leaf_hash_t16(finalFold)` (rate-8
  губка t=16 над 4 лимбами QM31, добавлена в `integration.rs`) пиннится в 8-словные leaf-столбцы.
  Value-bound end-to-end полностью in-circuit: finalFold (pinned) → hashLeaf_t16 → leaf8 (pinned) →
  t=16 путь → root (pinned). Капы входов с самого начала (урок R3.12).
- **Метод:** файлы сгенерированы систематическим t8→t16 преобразованием (структурная параллельность
  доказана паттерном) + ручная правка литеральных массивов; страховка — reference-driven тесты
  (trace против `compress_t16`/`merkle_path_root_t16`), поймавшие бы любую ошибку преобразования.
  Все 16 новых тестов прошли с первого прогона после исправления трёх size-аннотаций.
- **Итог лестницы:** t=2 (2^15.5) → t=8 (2^62) → **t=16 (~2^124 ≈ 128 бит)** — все три ступени
  in-circuit, каждая — чистый swap hash-backend'а при неизменном паттерне композиции.
  **150 рекурсивных тестов (505 всего), 0 предупреждений.**
- **Дальше (финальная фаза рекурсии):** on-chain интеграция — root vs committed FRI-layer root,
  channel-replay (challenges как public inputs), `QLSAVerifierRecursive.sol` + `BatchRegistryV7`.
  `docs/roadmap/recursion.md` § R3.18.

## Рекурсия R3.17 (2026-07-16) — 128-битный inner hash: t=16 перестановка + compression AIR

ФИНАЛЬНАЯ ступень лестницы inner-hash (t=2 → t=4 → t=8 → **t=16**): 8-словные (248-битные) узлы
поднимают стоимость коллизии узла до **~2^124 ≈ 128 бит** — целевой уровень soundness и ширина
нативного Stwo Poseidon2-16. По решению 2026-06-17 ценность t=16 — внутри рекурсии (on-chain газ
константен), не как standalone верификатор (~400M+ газа).

- **`poseidon2_t16.rs` — референс-перестановка:** R_F=8 (4+4), R_P=14, α=5 (Poseidon2 Table 1 для
  31-битных полей, t=16); внешняя матрица M_E = circ(2·M4, M4, M4, M4) (§5.1 block construction,
  M4 переиспользован из t=8); внутренняя M_I = J + diag(1..16) — обратимость доказана гауссовой
  элиминацией в тесте (det ≠ 0 над M31); RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t16" ‖ i_be4)[..4])
  mod P для i∈0..142 (документированное правило деривации, литералы заморожены). Rate-8/capacity-8
  губка с odd-length флагом в capacity-ячейке 15; `compress_t16(left[8], right[8]) → node[8]`.
  Frozen reference-векторы (регрессионные якоря). 6 тестов.
- **`recursive/poseidon2_t16_air.rs` — compression AIR:** арифметизация `compress_t16`, прямой
  t=16-аналог `poseidon2_t8_air`: 80 main-столбцов (in/sq/sbox/out/raw ×16) + 19 preproc (rc×16 +
  is_ext/is_int/is_first); один раунд на строку (22 раунда, LOG_SIZE=5); helper-столбцы `sq`/`sbox`
  держат x^5 на степени ≤3; обобщённые 16-ячеечные `mat_external16_expr`/`mat_internal16_expr`
  кросс-чекнуты против референс-слоёв ОТДЕЛЬНЫМ тестом (test_expr_layers_match_reference — прямая
  защита от soundness-бага в арифметизации линейного слоя); C2-пиннинг preproc. 7 тестов.
- **Валидация:** expr-слои ≡ референс; round-schedule ≡ permute_t16; trace node ≡ compress_t16
  (случайные входы); roundtrip; wrong-node/-input; corrupted-trace; forged-preproc (C2).
  **134 рекурсивных (489 всего), 0 предупреждений.**
- **Дальше:** t=16 Merkle-path AIR + composition_t16 (механический swap по паттерну R3.14/R3.15,
  оба раза сработавшему с первого прогона) → полный 128-битный inner-hash стек; затем on-chain
  интеграция (root vs committed FRI-layer root, `QLSAVerifierRecursive.sol`).
  `docs/roadmap/recursion.md` § R3.17.

## Рекурсия R3.16 (2026-07-16) — N-query широкая композиция (форма VFRI11 на t=8)

Масштабирование R3.15 до формы реального VFRI11-верификатора: N запросов + N широких путей в ОДНОМ
STARK — t=8-аналог N-query композиции R3.9. `prove_queries_membership_t8`/`verify_queries_membership_t8`
в `composition_t8.rs` + multi-path builders в `merkle_path_t8_air.rs`.

- **Multi-path t=8 builders** (`build_trace_multi`/`build_preproc_multi`/`compute_log_size_multi`):
  N путей однородной глубины в последовательных блоках по `depth` компрессий (22 строки каждая).
  **AIR не меняется** — пер-строчные селекторы `is_first_path` (сброс cur=leaf + пиннинг листа) и
  `is_root` (пиннинг корня) гейтят каждый путь в своём блоке; padding-строки продолжают round-chain
  с нулевыми селекторами (out форсится в 0).
- **Связка по каждому запросу q:** finalFold_q (pinned в rv) → leaf4_q = qm31_leaf_hash_t8(finalFold_q)
  (пересчитывается верификатором) → пиннится в leaf-столбцы пути q → root_q (pinned in-circuit).
- **Капы входов с самого начала (урок аудита R3.12):** MAX_QUERIES/MAX_NUM_FOLDS/MAX_DEPTH/диапазон
  log_size/ёмкость трейса в обоих prove/verify — враждебные входы дают Err, не панику/OOM.
- **Валидация:** 3-query roundtrip (finals/leaves/roots сверены с референсами) + пер-query rejection
  (wrong-final меняет пиннутый fin И пересчитанный leaf4; wrong-root меняет пиннутый root_q) +
  validation-errors (depth=0, mismatch, log_size=40). **2 теста, 127 рекурсивных (476 всего),
  0 предупреждений.**
- **Статус стека t=8:** compression AIR (R3.13) → path AIR (R3.14) → 1-query композиция (R3.15) →
  **N-query композиция (R3.16)** — широкий inner-hash стек рекурсии полностью повторяет форму
  верификации VFRI11 (N запросов, пути к FRI-layer корням) на коллизии узла 2^62.
- **Дальше:** t=16 (полные 128 бит — тот же swap), root vs committed FRI-layer root (on-chain
  интеграция), `QLSAVerifierRecursive.sol`. `docs/roadmap/recursion.md` § R3.16.

## Рекурсия R3.15 (2026-07-13) — широкая (t=8) композиция: recursive_verifier + merkle_path_t8

Интеграционный шаг: подключает t=8 path AIR (R3.14) как inner hash композиции рекурсии.
`recursive/composition_t8.rs` доказывает `recursive_verifier` (fold-цепочка, QM31) + `merkle_path_t8`
(4-словный путь) в ОДНОМ STARK — t=8-аналог `composition.rs`, меняющий inner hash с t=2 (31-битные
узлы, коллизия 2^15.5) на t=8 (4-словные узлы, 2^62). Это та самая per-query FRI-membership проверка,
которую делает VFRI11 on-chain, но теперь на широком хеше, который VFRI11 реально использует.

- **Связка (value-bound end-to-end, полностью in-circuit):** `finalFold` пиннится в `recursive_verifier`
  (fin-столбцы + is_output, C1) → верификатор off-circuit считает `leaf4 = qm31_leaf_hash_t8(finalFold)`
  (детерминированная публичная функция от пиннутого finalFold; `sponge_t8` над 4 лимбами, совпадает
  с `hash_leaf_qm31_p2t8` VFRI11-backend) → пиннит leaf4 в 4-словные leaf-столбцы `merkle_path_t8`
  (C1 leaf-binding) → t=8 путь аутентифицирует leaf4 @ index + siblings → root (C1 root-binding).
  Цепочка: finalFold (pinned) → hashLeaf_t8 → leaf4 (pinned) → t=8 path → root (pinned).
- **Тот же паттерн, что composition.rs (t=2):** меняется ТОЛЬКО inner-hash-гаджет; QM31 fold-цепочка
  и паттерн finalFold→leaf идентичны. 87 main + 39 preproc столбцов в объединённом STARK (rv 42/17 +
  merkle_t8 45/22). Объединённое Tree 0 пиннится одним каноническим корнем (C2). `qm31_leaf_hash_t8`
  добавлен в `integration.rs`.
- **Валидация:** roundtrip (fold-цепочка + t=8 membership в одном proof) + wrong-final (меняет пиннутый
  finalFold И пересчитанный leaf4 → иной канонический preproc-корень → reject) + wrong-root.
  `prove_query_membership_t8`/`verify_query_membership_t8`. **3 теста, 125 рекурсивных (474 всего),
  0 предупреждений.**
- **Эффект:** коллизия узла inner-hash рекурсии поднята с 2^15.5 (t=2) до **2^62** (t=8). t=16
  (полные 128 бит) — тот же swap, как только появится t=16 path AIR.
- **Дальше:** N-query t=8 композиция (форма VFRI11, как R3.9 после R3.8), затем t=16.
  `docs/roadmap/recursion.md` § R3.15.

## Рекурсия R3.14 (2026-07-13) — широкий inner-hash Merkle path: t=8 path AIR

Дуал R3.13 (`poseidon2_t8_air`), как `merkle_path_air` (t=2) к `poseidon2_merkle_air`.
`recursive/merkle_path_t8_air.rs` доказывает путь аутентификации Меркла по **4-словным/124-битным
узлам** через `compress_t8` — та самая структура, которую рекурсия воспроизводит для верификации
VFRI11 FRI-layer decommitment (узлы t=8). Поднимает коллизию узла inner-hash с 2^15.5 (текущий t=2
`merkle_path_air`) до 2^62.

- **Архитектурный ключ:** выход каждой компрессии (`out[0..4]`) ложится на её последнюю раунд-строку,
  которая смежна с первой строкой следующей компрессии → кросс-компрессионная цепочка `cur` использует
  маску `out[-1]` (тот же приём, что и t=2 путь), несмотря на 22 раунда/компрессию. Компрессия `c`
  занимает строки `c·22 .. c·22+22`; round-schedule периодичен с периодом 22.
- **Раскладка:** 45 main-столбцов — раунд-ядро `in`/`sq`/`sbox`/`out` ×8 (32, переиспользует
  `round_schedule`/`mat_external_expr`/`mat_internal_expr` из R3.13) + `cur[0..4]`/`sib[0..4]`/`bit`/
  `leaf[0..4]` (13, node-level). 22 preproc: `rc`×8 + `is_ext`/`is_int`/`is_first_comp`/`is_first_path`
  + `idx_bit` + `leaf_pin[0..4]` + `is_root` + `root_pin[0..4]`.
- **Node-level wiring:** `cur = is_first_path·leaf + (1−is_first_path)·out_prev[0..4]`; выбор left/right
  по биту (`raw = bit? (sib,cur):(cur,sib)`, 4-словные); `in[row0] = mat_external(raw)` через
  `is_first_comp`. Все ограничения ≤ степень 3.
- **C1 (всё in-circuit, зеркально on-chain `Poseidon2MerkleVerifierT8.verify(root,leaf,index,depth,siblings)`):**
  index (`is_first_comp·(bit−idx_bit)`), leaf (`is_first_path·(leaf−leaf_pin)`), root
  (`is_root·(out−root_pin)` на последней реальной компрессии). **C2:** пиннинг всего preproc через
  `canonical_preproc_root`.
- **Валидация:** reference-driven (honest trace из `merkle_path_root_t8`/`compress_t8`) + roundtrip
  depth 1/3/5 + rejection wrong-root/-leaf/-index/tampered + forged-root-cannot-prove (C1) +
  forged-preproc (C2). **11 тестов, 122 рекурсивных (471 всего), 0 предупреждений.**
- **Дальше:** подключить t=8 path AIR как inner hash композиции рекурсии (заменить/параметризовать
  t=2 `merkle_path_air` в `composition.rs`) → t=16 для полных 128 бит. `docs/roadmap/recursion.md` § R3.14.

## Рекурсия R3.13 (2026-07-13) — широкий inner-hash: Poseidon2 t=8 compression AIR

Первый широкий inner-hash-примитив рекурсии. `recursive/poseidon2_t8_air.rs` арифметизирует
Poseidon2 **t=8** компрессию (`compress_t8`: 8-словное состояние → 4-словный/124-битный узел,
коллизия узла ~2^62) как доказуемый AIR — широкий аналог t=2 `poseidon2_merkle_air` и та самая
хеш-функция, которой пользуется backend **VFRI11** (его FRI-layer Merkle-деревья на t=8). Это
следующая ступень на пути к 128-битной привязке (ограничение #6, лестница t=2→t=8→t=16) и
обязательный кирпич, чтобы рекурсия могла верифицировать реальное VFRI11-доказательство.

- **Раскладка:** один раунд на строку (4 внешних + 14 внутренних + 4 внешних = 22, паддинг до 32
  = LOG_SIZE 5). 40 main-столбцов (`in`/`sq`/`sbox`/`out`/`raw` ×8) + 11 preproc (`rc`×8 +
  `is_ext`/`is_int`/`is_first`). Helper-столбцы `sq=(in+rc)²`, `sbox=sq²·(in+rc)` держат S-box (x^5)
  на степени 3, поэтому out-констрейнт линеен → bound log+1 (как во всех AIR репо).
- **Линейные слои — точные выражения:** `mat_external` M_E=[[2M4,M4],[M4,2M4]] (M4=[[5,7,1,3],[4,6,1,1],
  [1,3,5,7],[1,1,4,6]]) и `mat_internal` J+diag(1..8). Начальный pre-mix `mat_external(raw)` инжектится
  на строке 0 через `is_first`; узел = `out[0..4]` на строке 21. Паддинг-строки продолжают chain
  (in=out_prev, out форсится в 0 нулевыми селекторами).
- **C2-пиннинг:** preproc — единый канонический источник `build_preproc`; верификатор пересчитывает
  корень Tree 0 (`canonical_preproc_root`) и отклоняет несовпадение (`test_forged_preproc_rejected`).
- **Валидация корректности (защита от soundness-бага):** honest trace строится из уже кросс-чекнутого
  эталона `permute_t8` (бит-в-бит совпадает с on-chain `Poseidon2M31T8.sol`) → неверный констрейнт
  роняет honest-proof на `ConstraintsNotSatisfied`, а не молча проходит. Тесты:
  `test_round_schedule_reproduces_permutation`, `test_trace_node_matches_reference`, roundtrip,
  wrong-node / wrong-input / corrupted-trace / forged-preproc. **7 тестов, 111 рекурсивных (460 всего),
  0 предупреждений сборки.**
- **Дальше:** t=8 Merkle-*path* AIR (дуал `poseidon2_t8_air`, как `merkle_path_air` к
  `poseidon2_merkle_air`) → подключить как inner hash рекурсии (коллизия узла 2^15.5 t=2 → 2^62 t=8)
  → t=16 (Stwo native, ~2^124 ≈ 128-бит). `docs/roadmap/recursion.md` § R3.13.

## Аудит (2026-07-10) — C1 root-binding закрыт для `merkle_path_air` (R3.12) + капы входов

Двухчастный аудит (крипто/блокчейн + код/высоконагруженные системы) свежей recursion-поверхности
R3.8–R3.11 (`composition.rs`, `recursive_verifier.rs`, `merkle_path_air.rs`, `QueryChallenges`).

- **[Крипто — ИСПРАВЛЕНО] Merkle `root` теперь пиннится in-circuit.** До фикса заявленный `root`
  был привязан только через Fiat-Shamir `mix_public`: честное доказательство нельзя было
  переиспользовать с другим root, но злонамеренный prover мог построить СВЕЖЕЕ доказательство для
  ЛОЖНОГО root-клейма — siblings являются свободным witness, а ограничения «вычисленный корень =
  заявленный» в схеме не было (тест `test_wrong_root_rejected` давал ложную уверенность: он
  проверял только неперееиспользуемость). Фикс — установленный паттерн пиннинга: preproc-столбцы
  `is_root`/`root` (единица на last-round-строке последней реальной компрессии каждого пути) +
  ограничение `is_root·(s0 − root_pinned) = 0`; `depth` стал явным public input
  `verify_merkle_path`/`verify_query_membership` (фиксирует строку пиннинга), зеркально on-chain
  `MerkleVerifier.verify(root, leaf, index, depth, siblings)`. Регрессия:
  `test_forged_root_cannot_prove`. Композиция single/N-query теперь value-bound end-to-end
  ПОЛНОСТЬЮ in-circuit: fin (fold output) → hashLeaf → leaf (pinned) → path → root (pinned).
- **[Код — ИСПРАВЛЕНО] Капы и валидации входов** добавлены в `composition::prove/verify_query(-ies)_membership`
  и `merkle::prove/verify_paths_multi` (в одиночных путях уже были): `MAX_QUERIES`/`MAX_NUM_FOLDS`/
  `MAX_DEPTH`/диапазон `log_size`/ёмкость трейса. Закрытые падения на враждебных входах: деление на
  ноль при `depth=0` (`comp / depth` в `build_preproc_multi`), OOB-запись в `build_preproc` при
  `num_folds` больше ёмкости блока, OOM-аллокация `1 << 40` при непроверенном `log_size`,
  паника-assert вместо `Err` при неоднородной глубине путей в `prove_paths_multi`.
- **Чистые зоны:** пиннинг Tree 0 во всех 6 верификаторах `lib.rs` подтверждён
  (`canonical_uh_preproc_root`×5 + `canonical_hashchain_preproc_root`); гейтинг селекторов,
  цепочка `out_prev`, границы блоков и degree-bound в `recursive_verifier` корректны; сканирование
  секретов (ключи/.env/private keys) — чисто; aggregator/sdk/testnet не менялись с аудита 2026-06-14.
- **Итог: 104 рекурсивных теста (453 всего), 0 предупреждений сборки.** После R3.12 остаётся:
  root vs *committed FRI-layer root* (on-chain интеграция), t=16 inner hash,
  `QLSAVerifierRecursive.sol`. `docs/roadmap/recursion.md` § R3.12.

## Аудит рекурсии (2026-06-17) — C1/C2 ЗАКРЫТЫ для `recursive_verifier` + robustness-фиксы

Двухэкспертный аудит (крипто/блокчейн + код/системы) полного набора рекурсивных gadget'ов
(`stark_stwo/src/recursive/`, R0.1–R3.6). Выявлены два composition-level пробела soundness; **оба
закрыты для флагманского composition-гаджета `recursive_verifier`** (single + N-query, 90 тестов):

- **[C1 — ИСПРАВЛЕНО] Привязка выхода.** Verifier-fixed заявленный final несётся в пиннутых
  preprocessed-столбцах `fin0..fin3`; in-circuit ограничение `is_output·(out − fin)=0` заставляет
  выходную строку трейса равняться ему → prover, чей трейс вычислил X, не может заявить Y≠X
  (regression `test_forged_output_cannot_prove`).
- **[C2 — ИСПРАВЛЕНО, был подтверждён пробой] Пиннинг preprocessed.** Селекторы + столбцы выхода
  производит единый источник `build_preproc`; верификатор пересчитывает commitment-корень
  (`canonical_preproc_root` через `CommitmentSchemeProver::roots()`) и отклоняет proof с иным
  `commitments[0]` → forged `is_step≡0` больше не верифицируется (regression
  `test_forged_selector_rejected`; раньше → `verify=true`).

**R3.7 follow-up — прогресс (2026-06-17):** C2-пиннинг портирован на **(а)** все 4 recursion sub-гаджета
(`merkle_path_air`/`channel_air`/`transcript_draw_air`/`fri_fold_chain_air` — `build_preproc(...)` +
`canonical_preproc_root` + `test_forged_preproc_rejected`) И **(б) все 5 production `is_init_uh`-верификаторов
в `lib.rs`** (`verify_use_hint_batch_v2`, `verify_norm_use_hint_combined`, `verify_az_ct1_norm_use_hint_combined`,
`verify_full_mldsa_witness_combined` V21/V22, `verify_full_mldsa_witness_v23`) через
`canonical_uh_preproc_root(max_log)` + `build_preproc_v2`: forged `is_init_uh≡0` (ослабил бы сброс
hint-weight-аккумулятора → мог обойти границу OMEGA) больше не верифицируется; honest V21/V22/V23
roundtrip'ы проходят. **C2 закрыт для ВСЕХ preprocessed-верификаторов репо (2026-06-17):** + Poseidon2 hash-chain
`verify_hash_chain_poseidon2`. Ни один верификатор не принимает непиннутое Tree 0.
**R3.8 — первая multi-gadget рекурсивная композиция (2026-06-17):** `recursive/composition.rs` доказывает
`recursive_verifier` + `merkle_path` в ОДНОМ multi-component STARK — per-query fold-цепочка →
`hashLeaf(finalFold)` → Merkle-корень, привязано end-to-end (finalFold пиннится fin-столбцами; leaf пиннится
в merkle через C1 leaf-binding; объединённое Tree 0 пиннится). `prove_query_membership`/`verify_query_membership`,
3 теста. **99 рекурсивных тестов.** Осталось до полного верификатора: связать `channel` (absorb→draw) для
channel-derived challenges, масштабировать до N запросов, on-chain `QLSAVerifierRecursive.sol`.
**Robustness:** cap'ы, guard'ы, assert'ы. `docs/roadmap/recursion.md` § R3.8.

## Статус (обновлено 2026-06-17 — решение по пути: standalone t=16 пропущен, старт рекурсии)

- **Решение по пути (2026-06-17)**: standalone **t=16-верификатор (VFRI12) ПРОПУЩЕН** — вместо него идём сразу к **рекурсии доказательств**.
  - Обоснование: отдельный on-chain t=16-верификатор имеет ту же газовую стену, что t=8, но ~×4 хуже (~400M+ газа на полный V23) — доказал бы корректность только на depth-4 toy-масштабе, никогда не задеплоил бы production V23.
  - t=16 (~2^124 ≈ 128-бит, = нативный Poseidon2-16 в Stwo) — целевой уровень коллизии узла, но его ценность **внутри inner hash AIR рекурсивного доказательства**, где on-chain газ константен независимо от ширины перестановки.
  - Рекурсия даёт ОБА результата за один шаг: 128-бит soundness И production-feasible константный газ (~5M).
  - Лестница t=2/t=4/t=8 остаётся в репо как кросс-проверенный soundness-сертификат; t=16 переезжает внутрь рекурсии.
  - Полный план: `docs/roadmap/recursion.md`. Код: `stark_stwo/src/recursive/`.

- **Рекурсия R0.1 (2026-06-17)**: первый foundational gadget — `stark_stwo/src/recursive/qm31_mul_air.rs`
  - QM31 batch-multiply AIR: доказывает `z = x·y` в QM31 = CM31[u]/(u²−R), R = 2+i; 12 cols (x:4,y:4,z:4), 4 ограничения степени 2, без preproc
  - Несущий примитив рекурсивного верификатора (circleFold/lineFold/OODS сводятся к QM31-арифметике)
  - Полный Stwo prove/verify roundtrip + кросс-чек против u128-референса (`u²=R`, `1·y=y`); 8 Rust тестов (вкл. 2 rejection)

- **Рекурсия R1 + R0.3 (2026-06-17)**: FRI fold gadget + rejection-харнесс
  - `stark_stwo/src/recursive/fold_air.rs`: circle/line fold AIR — `folded = (f₊+f₋) + α·(f₊−f₋)·inv` (единая формула; inv=y⁻¹ для circle, x⁻¹ для line). 21 col, helper-столбец `p=(f₊−f₋)·inv` снижает степень 3→2 (C_p:4 + C_f:4, все deg 2)
  - Кросс-чек `fold_ref ≡ vfri2_bridge::circle_fold`; алгебраические инварианты (α=0⇒sum, f₊=f₋⇒2·f₊); полный prove/verify roundtrip; 8 Rust тестов
  - **R0.3 rejection-харнесс**: оба gadget'а получили `prove_columns` (вынесен из prove) → тесты подают испорченный trace-столбец (product/folded/helper-p) и подтверждают, что proof не верифицируется (+байтовый tamper). Закрывает Low-1 аудита (раньше были только позитивные тесты)

- **Рекурсия R1 завершён — OODS quotient (2026-06-17)**: `stark_stwo/src/recursive/oods_air.rs`
  - OODS quotient AIR: доказывает `fₚ·(px − z_x) = compValue − oodsCombo` (мультипликативная форма, без QM31-inv) — перегруппировка верификаторного `fPlus=(rawComp−oodsCombo)/(px−z_x)`
  - 17 col, 4 ограничения степени 2; `px` (M31) встраивается в QM31 как `(px,0,0,0)`; одна форма покрывает позитивный (`px`) и антиподальный (`−px`) запрос
  - Кросс-чек против `vfri2_bridge`; алгебраический инвариант (fₚ=0 ⇒ compValue=oodsCombo); roundtrip + 2 rejection; 8 Rust тестов
  - **R1 полностью завершён**: все 3 арифметических FRI-примитива (QM31-mul, fold, OODS) готовы и cross-checked против on-chain референса; **24 рекурсивных Rust теста зелёные**. Следующее: R2 — Poseidon2-t16 inner-hash Merkle AIR

- **Рекурсия R2 — Merkle auth-path AIR (2026-06-17)**: `stark_stwo/src/recursive/merkle_path_air.rs`
  - Доказывает путь аутентификации: `leaf @ index + siblings → root` через Poseidon2 t=2 compression (on-chain `MerkleVerifier.verify` переведён в AIR; dual к full-tree `poseidon2_merkle_air`)
  - 10 main + 4 preproc col; раскладка 8 раундов/компрессия. Новое поверх раунд-ядра: выбор left/right по биту индекса (`bit·sib+(1−bit)·cur`), цепочка `cur` между компрессиями (`cur = is_first·leaf + (1−is_first)·s0[-1]`), привязка `(leaf,index,root)` в Fiat-Shamir канал. Все ограничения ≤ deg 3
  - Кросс-чек `merkle_path_root` ↔ прямые `compress`; roundtrip depth 1/3/5; rejection (wrong root/index/tampered/corrupted-trace). 10 Rust тестов
  - Самый дорогой блок рекурсивного верификатора (путь на запрос на FRI-слой). **34 рекурсивных Rust теста зелёные**

- **Рекурсия R2 — Fiat-Shamir transcript AIR (2026-06-17)**: `stark_stwo/src/recursive/channel_air.rs`
  - Доказывает поглощение Poseidon2 t=2 duplex-губки (`mixU32s`-ядро `Poseidon2Channel`/`P2T8Channel`): `s0 += word; permute` → digest. Рекурсивный верификатор воспроизводит транскрипт в схеме, чтобы доказать честный вывод challenge'ов/позиций запросов
  - 7 main + 4 preproc col; init-wiring `inp0 = (is_first?0:s0[-1]) + word`; привязка `(n_words, digest)` в канал. Кросс-чек ↔ прямой `permute`; roundtrip 1/8 слов; rejection (wrong digest/count/tampered/corrupted-trace). 9 Rust тестов
  - **Полный набор gadget'ов готов**: арифметика (QM31-mul), FRI-фолд, OODS, inner-hash Merkle path, Fiat-Shamir transcript — все 5 категорий. **43 рекурсивных Rust теста зелёные**

- **Рекурсия R3.1 — per-query FRI step (2026-06-17)**: `stark_stwo/src/recursive/query_step_air.rs`
  - Первый composition-gadget: в одной строке на запрос объединяет OODS± + circle fold, где `fPlus`/`fMinus` текут из OODS в fold **через общие trace-столбцы** (реальная data-flow рекурсивного верификатора, не отдельный proof)
  - `OODS+: fPlus·(px−z_x)=compPos−comboPos`, `OODS−: fMinus·(−px−z_x)=compNeg−comboNeg`, `fold: folded=(fPlus+fMinus)+α·(fPlus−fMinus)·yInv`. 42 col, helper `p=(fPlus−fMinus)·yInv` держит все 16 ограничений ≤ deg 2; generic `qmul` дедуплицирует раскрытие QM31-mul
  - Кросс-чек: куски шага ≡ `oods_air::comp_value_ref` (px и −px) + `fold_air::fold_ref`; roundtrip + 2 rejection. 7 Rust тестов. **50 рекурсивных Rust тестов зелёные**
  - Следующее: t=16 inner hash (pluggable backend) + полный recursive_verifier (per-query steps + Merkle + transcript в одном proof)

- **⚠️ Git-инцидент (2026-06-17)**: между ходами контейнер пере-склонировался, локальные origin-ref'ы устарели до merge-коммита `36cfc3e` (казалось, R1/R2-коммиты потеряны). `git fetch` восстановил `origin/...E4kPW` до `657e87b` (forced update) — коммиты были на реальном remote. `git reset --hard` восстановил рабочее дерево. Урок: после «потери» коммитов сначала `git fetch`, прежде чем считать их утраченными

- **Аудит безопасности + code review (2026-06-17)**: 2 эксперта (crypto/blockchain + Rust/системы) по диффу VFRI11/t=8/рекурсия против main. **Нет Critical/High/Medium.** QM31-формула рекурсивного gadget проверена вручную — корректна, soundness-пробела нет (4 ограничения точно фиксируют каждый limb z). Исправлено/упрочнено:
  - **deploy_v6.sh (HIGH, fixed)**: флаг `--network` молча игнорировался (`NETWORK="${1:-sepolia}"` ставил `NETWORK="--network"`) → риск деплоя в неверную сеть. Добавлен полноценный парсинг `--network[=]val` + `-h`
  - **deploy_v6.sh (LOW, fixed)**: `.env.deployed` создаётся `umask 077` (0600) — гигиена перед append в `.env` (хранит `DEPLOYER_PRIVATE_KEY`)
  - **e2e.py (MED, fixed)**: `--n-queries`/`--txs` теперь валидируются `>= 1` (раньше `0`/негатив давали бессмысленный security_bits и UB на стороне прувера)
  - **submit.py (MED, fixed)**: web3 `HTTPProvider(..., request_kwargs={"timeout":30})` на всех 3 провайдерах — зависший RPC больше не блокирует поток дольше `confirm_timeout_s`
  - **Poseidon2M31T8.sol (LOW, fixed)**: `sponge` редуцирует входные слова `% P` — точное соответствие Rust `sponge_t8` даже для non-canonical слов ≥ P (defense-in-depth; в VFRI-пайплайне входы всегда — QM31-лимбы < P). Замороженные cross-check векторы не сдвинулись (24 T8-теста зелёные)
  - **qm31_mul_air.rs (LOW, fixed)**: задокументирована предусловие каноничности limbs (< M31_P) + `debug_assert` в `build_trace`; комментарий о границе входов в `m31_mul`
  - **Задокументировано как non-exploitable / accepted**: версия-маркер `proof[0:8]=5` не проверяется on-chain (уже связан через commitment Blake2s(proof[:32]‖root); идентично задеплоенному VFRI10); estimateGas-preflight в submit отсутствует намеренно (избегает падения на большом calldata); broad-except в PyO3-обёртках консистентен с VFRI10; OnchainSubmitterV6 не concurrency-safe (single-threaded e2e)
  - **Verified-OK**: VFRI11 — точный backend-swap VFRI10 (Fiat-Shamir порядок, M31-редукция в `_absorb`, Merkle node encoding, cross-bound binding BatchRegistryV6, replay/nonce/griefing); poseidon2_t8 матрицы/RC/S-box bit-exact; PyO3-граница panic-safe; release build warning-free

## Статус (2026-06-16 — VFRI11 V23 pipeline + верификатор + Poseidon2 t=8 backend)

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
- **VFRI9 aggregator pipeline (2026-06-12)**: `BatchResult` + `has_vfri9` + `vfri9_proof/commitment/hints_log{10,8}`; `Batcher._try_prove` вызывает `prove_mldsa_sig_vfri9_stark`; API `/batch/run`/`/batch/flush`/`/batch/{id}`/`/batch/{id}/witness`/`/batches` возвращают `has_vfri9` + commitments; Python SDK `WitnessStatus`/`BatchStatus` + `LocalClient`/`HttpClient` обновлены
- **pyo3 0.24→0.29 CVE fix (2026-06-12)**: устранены RUSTSEC-2026-0176 (OOB read в `PyList`/`PyTuple` nth/nth_back) и RUSTSEC-2026-0177 (missing `Sync` на `PyCFunction::new_closure`); только version bump + lockfile update, никаких изменений исходников
- **JS SDK VFRI9 parity (2026-06-12)**: `types.ts` — `WitnessStatus`/`BatchStatus` получили `hasVfri9`/`vfri9CommitmentLog{10,8}`; `client.ts` — 5 inline копий wire-типа консолидированы в `RawBatchStatus` interface + `_toBatchStatus` helper
- **Poseidon2 t=4 (MVP-6 groundwork, 2026-06-12)**: `stark_stwo/src/poseidon2_t4.rs` — полный R_F=8 + R_P=21 пермутатор, rate-2 capacity-2 sponge (флаг odd-length в capacity cell s[3]), `compress_t4` для 124-bit wide nodes; 12 Rust тестов с frozen reference vectors. `contracts/src/verifier/Poseidon2M31T4.sol` — Solidity зеркало; 11 JS тестов. Vectors заморожены кросс-языково. VFRI10 не подключён — see Known Limitations #6
- **Тесты (2026-06-12)**: 315 Rust (+12 poseidon2_t4, +88 ignored), 917 Hardhat (+11 Poseidon2M31T4)
- **VFRI10 hash backend (2026-06-13)**: t=4 wide Merkle + Fiat-Shamir channel поверх готового `poseidon2_t4`
  - `contracts/src/verifier/Poseidon2MerkleVerifierT4.sol` — узлы 2 слова `(s0<<32)|s1` (как W), но t=4: `sponge` для листьев, `compress` (4→2) для пар; 124-бит состояние, 2-cell capacity
  - `contracts/src/verifier/Poseidon2ChannelT4.sol` — t=4 duplex sponge: absorb rate-1 в cell 0 (capacity 93 бит), draw squeeze (s0,s1); mixRoot/mixRootW/mixRootFull/mixU32s/drawSecureFelt/drawQueries
  - Rust references в `vfri2_bridge.rs`: `hash_leaf_cols_p2t4`/`hash_pair_p2t4`/`hash_leaf_qm31_p2t4`/`build_tree_p2t4`/`P2T4Channel` (#[allow(dead_code)] до подключения VFRI10 верификатора)
  - Cross-check заморожен: `hashLeaf([1,2,3,4])→(188265029,348838750)`, `hashPair((1,2),(3,4))→(1706601437,1471208702)`, `mixRoot(0x11..).drawQueries(10,4)→[674,500,407,375]`
  - 6 Rust тестов (`p2t4`) + 12 JS тестов (`Poseidon2T4Backend.test.js`); остаётся подключить VFRI10 верификатор-контракт
- **Тесты (2026-06-13)**: 321 Rust (+6 p2t4, 89 ignored), 929 Hardhat (+12 Poseidon2T4Backend)
- **VFRI10 верификатор (2026-06-13)**: `QLSAVerifierVFRI10.sol` — протокол VFRI9 с t=4 hash backend
  - Только смена backend: `Poseidon2MerkleVerifierW→Poseidon2MerkleVerifierT4`, `Poseidon2Channel→Poseidon2ChannelT4`; ABI хинтов байт-в-байт как у VFRI9 (6 head slots), last-layer FRI check сохранён, маркер версии `proof[0:8]=4`
  - Rust-мост `gen_vfri10_hints_from_cols_nfolds` — копия VFRI9-моста с 5 заменами backend, переиспользует ABI-энкодер VFRI9
  - Fixture `contracts/test/fixtures/vfri10_e2e.json` (6 cols, depth=4, 2 queries, 2 folds) генерится `cargo test write_vfri10_e2e_fixture -- --ignored`
  - On-chain `verify()==true` (≤16.7M gas для малого fixture); t=4 хинты НЕ принимаются VFRI9 верификатором (разная перестановка → разные query indices)
  - 2 Rust smoke-теста + 11 JS E2E тестов; остаётся V23 cross-bound обёртки (`gen_mldsa_v23_vfri10_*`) + PyO3/Python + реестр для aggregator-пути
- **Тесты (2026-06-13, VFRI10)**: 323 Rust (+2 vfri10, 90 ignored), 940 Hardhat (+11 QLSAVerifierVFRI10E2E)
- **VFRI10 production pipeline (2026-06-14)**: V23 cross-bound обёртки + PyO3 + Python + on-chain dual E2E
  - Rust V23 мосты: `gen_mldsa_v23_vfri10_hints` (LOG=10, 1298), `gen_mldsa_v23_vfri10_hints_log8` (LOG=8, 2206), `gen_mldsa_v23_vfri10_cross_bound_hints` (two-pass keccak256)
  - PyO3: `gen_mldsa_v23_vfri10_hints_py` / `_log8_py` / `_cross_bound_hints_py`
  - Python (`stark/prover.py`): `gen_mldsa_v23_vfri10_hints[_log8]`, `gen_mldsa_v23_vfri10_cross_bound_hints`, `prove_mldsa_sig_vfri10_stark` + результаты `MldsaV23VFRI10HintResult`/`...Log8...`/`FullV23VFRI10CrossBoundHintResult`
  - `BatchRegistryV5` подключает VFRI10 через конструктор (verifier-agnostic); on-chain оба группы verify()==true индивидуально
  - **Gas finding**: каждая V23-группа verify() ≤16.7M gas по отдельности (~8–10M); dual-group submitBatch (обе t=4 проверки в одной tx) превышает 16.7M per-tx cap. `num_folds=6` обязателен (last layer 16/4 evals); `num_folds=3` (128 evals) превышает cap уже на LOG=10. Production: per-group реестр (одна проверка на tx) или mainnet 30M
  - 8 Python тестов (`tests/test_stark_stwo.py`) + 10 JS V23 cross-bound E2E + фикстура `full_v23_vfri10_cross_bound_e2e.json`
- **Тесты (2026-06-14)**: 323 Rust, 210 stark_stwo Python (+8 vfri10), 950 Hardhat (+10 QLSAVerifierVFRI10CrossBoundE2E)
- **Security + code audit (2026-06-14)**: 2 эксперта (crypto/blockchain + systems). Найдено 9, исправлено 6, 1 false-positive, 2 задокументированы как research-defaults:
  - **H1 (fixed)**: off-chain replay — уже забатченную tx можно было пересабмитить и забатчить снова (mempool dedup покрывает только pending). Добавлен `ReplayedTxError` guard в `AggregatorNode.submit()` (отклоняет re-submission tx из retained history `_tx_to_batch`); on-chain nonce registry — durable backstop
  - **H2 (false positive)**: `_sender_txs` unbounded — проверено: ограничен 1000-batch history eviction (только забатченные tx, пустые deque удаляются, per-sender cap 500). Не уязвимость
  - **L2 (fixed)**: `POST /transactions` возвращал raw `str(exc)` → leak внутренних деталей; теперь fixed-сообщения (`invalid transaction` / `mempool full`), детали в server-side log
  - **L4 (fixed)**: `/stats` теперь отдаёт `mempool_dropped` (потери prepend_batch overflow)
  - **MEDIUM code (fixed)**: `vfri2_bridge.rs:5399 mod tests` без `#[cfg(test)]` → тест-фикстуры (`make_v23_inputs`/`make_vfri5_polys`/`make_log8_hints`) компилировались в production lib (5 warnings). Gated; release build чист
  - **LOW code (fixed)**: `poseidon2_t4.rs` import `m31_mul` использовался только в тестах → перенесён в test-модуль
  - **Latent (hardened)**: generic FRI генераторы VFRI9/VFRI10 теперь валидируют `tree_depth ∈ 2..=30` (зеркалит on-chain `logDomainSize > 30`), предотвращает `coset_at` shift underflow; не attacker-reachable (V23 wrappers фиксируют depth 8/10)
  - **Verified-OK**: Bearer-token constant-time, Merkle `hmac.compare_digest`, mempool locking, нет unsafe deserialization/SSRF/ReDoS; VFRI10 ≡ VFRI9 кроме backend+marker; t=4 Poseidon2 математика (M4 fast-path) верна; PyO3 boundary не паникует на malformed input
  - **Documented research-defaults (unchanged)**: M1 XFF-spoofing зависит от proxy-конфига; M2 `/batch/*` открыт без `QLSA_API_TOKEN` (warning при старте); L1 ML-DSA key copies в CPython не зануляются
- **Тесты после аудита (2026-06-14)**: 354 non-PyO3 Python (+4 replay-тесты), mypy clean, Rust release warning-free
- **BatchRegistryV6 — per-group split (2026-06-14)**: закрывает gas-wall dual-verify для t=4 backend
  - `submitGroup10` / `submitGroup8` — по одному `verify()` на транзакцию (LOG=10 ~10.6M gas, LOG=8 ~7.9M gas, оба ≤16.7M); auto-finalize когда обе группы present И cross-consistent
  - `submitGroup8WithNonces` — завершающий вызов с per-sender nonce enforcement (требует group10 present & consistent, иначе `NotReadyToFinalize`)
  - Cross-proof binding сохранён lazy: verify против `keccak256(merkleRoot ‖ crossTraceRoot)` на submit; на finalize проверка `crossRoot8For10 == traceRoot8` и `crossRoot10For8 == traceRoot10` (каждый proof привязан к реальному trace root другого) — та же soundness, что у атомарного V5, но через 2 tx
  - Order-independent; не-финализированную группу можно перезаписать (нет front-run griefing lock); pending state `delete` на finalize (storage refund)
  - Полный V23 t=4 verify теперь deployable на 16.7M-cap сети через 2 транзакции
  - 8 JS E2E тестов (`BatchRegistryV6E2E.test.js`); 958 Hardhat (+8)

- **Testnet tooling для MVP-6 (2026-06-16)**: деплой/E2E цепочка подключена к продакшн-стеку VFRI10 + BatchRegistryV6
  - `contracts/scripts/deploy_v6.js` + `testnet/deploy_v6.sh` — деплой `QLSAVerifierVFRI10` + `BatchRegistryV6`, запись адресов в `.env.deployed`
  - `testnet.submit.OnchainSubmitterV6` — per-group split поток: `submit_group10()` → `submit_group8_with_nonces()`; `finalize_batch(merkle_root, vfri10_result, senders, nonces)` гоняет обе tx (cross trace root каждой группы извлекается из `proof[8:40]` другой); ABI сверен byte-for-byte с артефактом контракта
  - `python -m testnet.e2e --stack v6` (default) — `prove_mldsa_sig_vfri10_stark` с `num_folds=6` (gas budget); `--stack v4` сохраняет MVP-5 путь (VFRI7 + BatchRegistryV4) для регрессии
  - `testnet/monitor.py` совместим с V4 и V6 (идентичная сигнатура `BatchFinalized`)
  - Проверено: оба dry-run (`v6`/`v4`) генерируют реальные cross-bound proofs; `deploy_v6.js` деплоит оба контракта; ABI совпадает

- **Poseidon2 t=8 — следующая ступень к 128-bit binding (2026-06-16)**: groundwork-перестановка, кросс-чек Rust↔Solidity bit-exact
  - Уточнение диагноза: стену ~2^31 держит **ширина узла**, а не семейство хеша — VFRI10 (t=4) усекает Merkle-узлы до 2 слов M31 (62 бита → 2^31). Дешёвый рычаг к 128 битам — **широкий Poseidon2**, а не RPO256 (x^5 forward S-box остаётся дешёвым на EVM, без инверсного S-box)
  - `stark_stwo/src/poseidon2_t8.rs` + `contracts/src/verifier/Poseidon2M31T8.sol`: t=8, R_F=8, R_P=14, α=5, блочная внешняя матрица `[[2·M4,M4],[M4,2·M4]]`, внутренняя J+diag(1..8), RC[0..78] из SHA-256("QLSA-Poseidon2-t8"‖i)
  - `compress` несёт **4-словные (124-бит) узлы → коллизия ~2^62** (vs 2^31 у VFRI10); rate-4 capacity-4 sponge, odd-flag в capacity cell s[7]
  - Reference vectors заморожены и сверены: 11 JS (`Poseidon2M31T8.test.js`) + 12 Rust тестов; matrices invertible, fast-path == naive, полная диффузия
  - **Лестница:** t=2/t=4 (2^31) → **t=8 (2^62)** → t=16 (8-словные узлы, ~2^124 ≈ 128-bit, = нативный Poseidon2-16 в Stwo)
  - Release build чистый (warning-free)

- **t=8 hash backend (2026-06-16)**: Merkle-верификатор + Fiat-Shamir канал на t=8 перестановке, кросс-чек bit-exact
  - `contracts/src/verifier/Poseidon2MerkleVerifierT8.sol` — **4-словные (124-бит) узлы** `(w0<<96)|(w1<<64)|(w2<<32)|w3` (bytes[16..32]); `hashLeaf` = rate-4 cap-4 sponge, `hashPair` = 8→4 compress; коллизия узла 2^31 (T4) → **2^62**
  - `contracts/src/verifier/Poseidon2ChannelT8.sol` — состояние (s0..s7, nDraws), rate-1 absorb в cell 0 (cells 1–7 = 217-бит capacity); mixRoot/mixRootW(4 слова)/mixRootFull/mixU32s/drawSecureFelt/drawQueries
  - Rust references в `vfri2_bridge.rs` (#[allow(dead_code)] до VFRI11): `hash_leaf_cols_p2t8`/`hash_pair_p2t8`/`hash_leaf_qm31_p2t8`/`build_tree_p2t8`/`P2T8Channel`
  - Reference vectors заморожены и сверены: **13 JS** (`Poseidon2T8Backend.test.js`) + **6 Rust** (`p2t8`); Merkle inclusion E2E, full-root binding

- **VFRI11 верификатор (2026-06-16)**: протокол VFRI10 на t=8 хеш-бекенде — on-chain `verify()==true`
  - `contracts/src/QLSAVerifierVFRI11.sol` — клон VFRI10 с заменой `Poseidon2MerkleVerifierT4`→`T8`, `Poseidon2ChannelT4`→`T8`; ABI идентичен VFRI9/10 (6 head slots); marker proof[0:8]=5
  - Узлы 2 слова (62-бит) → **4 слова (124-бит)** → коллизия узла/транскрипта 2^31 → ~2^62; last-layer FRI check + full-root FS сохранены
  - `Poseidon2M31T8._matI` оптимизирован на 1 `mulmod`/ячейку (== Rust repeated-add reference) → generic `verify()` **~13.1M gas** (depth=4, 2 queries, 2 folds), влезает в 16.7M cap
  - Rust bridge `gen_vfri11_hints_from_cols_nfolds` (клон VFRI10 + 5 t8-замен); 3 Rust smoke + **11 JS E2E** (`QLSAVerifierVFRI11E2E.test.js`); фикстура `vfri11_e2e.json`
  - Backend-mismatch: VFRI11 хинты НЕ принимаются VFRI10 (разная перестановка → разный trace root)

- **VFRI11 V23 production pipeline (2026-06-16)**: cross-bound обёртки + PyO3 + Python + structural E2E
  - Rust: `gen_mldsa_v23_vfri11_hints[_log8]`, `gen_mldsa_v23_vfri11_cross_bound_hints` (клоны VFRI10-обёрток, вызывают `gen_vfri11_hints_from_cols_nfolds`)
  - PyO3: `gen_mldsa_v23_vfri11_hints_py` / `_log8_py` / `_cross_bound_hints_py` (wheel пересобран и установлен)
  - Python (`stark/prover.py`): `gen_mldsa_v23_vfri11_hints[_log8]`, `gen_mldsa_v23_vfri11_cross_bound_hints`, `prove_mldsa_sig_vfri11_stark` + dataclasses `MldsaV23VFRI11HintResult`/`...Log8...`/`FullV23VFRI11CrossBoundHintResult`
  - **7 Python тестов** (markers==5) + **8 JS structural E2E** (`QLSAVerifierVFRI11CrossBoundE2E.test.js`, `BatchRegistryV5` подключён к VFRI11); фикстура `full_v23_vfri11_cross_bound_e2e.json` (seed=16600, num_folds=6) via `gen_full_v23_vfri11_fixture.py`
  - **Gas finding**: on-chain `verify()` полной V23 t=8 группы **превышает 100M газа** на depth-10 (estimateGas упирается в 100M block limit) — t=8 перестановка ~3–4× t=4, плюс depth-10 Merkle paths + 6 fold rounds. Корректность t=8 on-chain доказана на малом масштабе (generic depth-4, ~13.1M, `verify()==true`). Production полной V23 t=8 требует рекурсии (константный газ); широкая перестановка повышает стойкость, но не газовый бюджет
  - Следующее: t=16 (8-словные узлы → полные 128 бит) для лестницы soundness; рекурсия для production-газа

- **VFRI10 в пайплайне агрегатора (2026-06-16)**: продакшн-нода теперь генерирует VFRI10 witness-proofs (раньше только VFRI7/8/9)
  - `aggregator/batcher.py`: `BatchResult` несёт поля `vfri10_{proof,commitment,hints}_{log10,log8}`, свойство `has_vfri10`, добавлено в `has_witness`; генерация через `prove_mldsa_sig_vfri10_stark` с `Batcher.VFRI10_NUM_FOLDS = 6` (gas budget BatchRegistryV6)
  - `aggregator/api.py`: все 6 witness-эндпоинтов отдают `has_vfri10` / `vfri10_commitment_log{10,8}`
  - Python SDK (`models.py` `WitnessStatus`/`BatchStatus`, `client.py` Local+HTTP): поля VFRI10 проброшены; `_prove_witness_local` гоняет VFRI10
  - JS SDK (`types.ts`, `client.ts`): `hasVfri10` / `vfri10CommitmentLog{10,8}` в `BatchStatus`/`WitnessStatus` + snake_case маппинг
  - Тесты: интеграционный `test_vfri10_populated_and_version4_when_proving` (проверяет marker==4, реальный прувер), расширены aggregator/sdk Python + JS client/types тесты
  - Проверено: 264 Python (aggregator+sdk+api) + 66 JS + mypy strict + tsc --noEmit — всё зелёное

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
- Python: **~350 тестов** (без PyO3) / **~552** (с PyO3 ext)
- Rust: **323 тестов** (cargo test, non-ignored) + **90 ignored** (slow STARK integration tests incl. V23)
- Python (stark_stwo): **210 тестов** (+8 VFRI10 V23)
- TypeScript SDK: **~71 тестов** (jest)
- Solidity/Hardhat: **958 тестов** (+8 BatchRegistryV6E2E.test.js)
- mypy --strict: `core/ aggregator/` (exclude `aggregator/api`) — чистые

#### Деплой
- Сеть: **Ethereum Sepolia** (2026-05-05)
- Первый батч финализирован: 4 транзакции, 3234 байт proof, 9.16 секунды
- `testnet/e2e.py --stack v6` — end-to-end тест с реальными подписями (VFRI10 + BatchRegistryV6 по умолчанию; `--stack v4` для MVP-5)
- Деплой продакшн-стека: `bash testnet/deploy_v6.sh` (VFRI10 + BatchRegistryV6); MVP-5: `bash testnet/deploy.sh`

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
| **VFRI9 pipeline** | **✅ Done** | **Aggregator BatchResult + API + Python SDK + JS SDK expose VFRI9 commitments (2026-06-12)** |
| **pyo3 CVE fix** | **✅ Done** | **pyo3 0.24→0.29: RUSTSEC-2026-0176 + RUSTSEC-2026-0177 (2026-06-12)** |
| **Poseidon2 t=4** | **✅ Done (groundwork)** | **Rust + Solidity cross-checked permutation; 124-bit compress; 315 Rust + 917 Solidity tests (2026-06-12)** |
| **VFRI10 hash backend** | **✅ Done** | **t=4 wide Merkle (`Poseidon2MerkleVerifierT4`) + Fiat-Shamir channel (`Poseidon2ChannelT4`) + Rust refs, cross-checked; 321 Rust + 929 Solidity (2026-06-13)** |
| **VFRI10 верификатор** | **✅ Done** | **`QLSAVerifierVFRI10.sol` — VFRI9-протокол на t=4 backend; `gen_vfri10_hints_from_cols_nfolds`; on-chain verify()==true; 323 Rust + 940 Solidity (2026-06-13)** |
| **VFRI10 production pipeline** | **✅ Done** | **V23 cross-bound обёртки + PyO3 + Python + on-chain dual E2E; per-group verify ≤16.7M; 210 Python + 950 Solidity (2026-06-14)** |
| **BatchRegistryV6** | **✅ Done** | **Per-group split: 1 verify()/tx (теперь 2.15M / 1.70M gas). После R4.8 split опционален — единый `BatchRegistryV5.submitBatch` укладывается в cap (3.74M для t=4) (2026-06-14; газ 2026-07-30)** |
| **VFRI11 (t=8)** | **✅ Done** | **VFRI10-протокол на Poseidon2 t=8 backend (4-словные/124-бит узлы → 2^62); full-V23 t=8 on-chain: LOG=10 3.34M / LOG=8 2.63M, dual submitBatch 6.06M в одной tx (2026-06-16; газ пересчитан 2026-07-30, R4.8)** |
| **t=16 standalone** | **⏭️ SKIPPED** | **Решение 2026-06-17: газовая стена ~×4 хуже t=8; t=16 переезжает внутрь рекурсии как inner hash AIR** |
| **Рекурсия** | **⏳ IN PROGRESS** | **STARK, доказывающий VFRI11-верификацию → константный ~5M газа on-chain + inner hash любой ширины (t=16/RPO256) бесплатно. `docs/roadmap/recursion.md`, `stark_stwo/src/recursive/`** |

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
| Poseidon2Channel t=2/M31 = 62-bit state (ниже 128-bit target sponge security) | Высокий | Частично смягчён (2026-06-10): VFRI9 wide nodes 31→62 бит + mixRootFull. Groundwork MVP-6 готов (2026-06-12): `poseidon2_t4.rs` + `Poseidon2M31T4.sol` cross-checked (t=4, 124-bit compress, collision ~2^62). VFRI10 не подключён — полные 128 бит требуют t≥4 wire-up |
| Узлы Poseidon2 Merkle в VFRI8 = 31 бит (s0 only) — коллизия листа ~2^15.5 | Высокий | ✅ Закрыт в VFRI9 (`Poseidon2MerkleVerifierW`, узел = `(s0<<32)\|s1`); VFRI8 — регрессионный, не деплоить |
| Транзакции терялись при крахе прувера (батч с proof=None уходил в историю) | Высокий | ✅ Закрыт (Batcher retry ≤3 + возврат в мемпул через prepend_batch, 2026-06-10) |
| `prepend_batch` молча терял транзакции при переполнении мемпула | Средний | ✅ Закрыт (возврат списка потерянных, oldest-kept, метрика dropped_count, 2026-06-10) |
| Нет аутентификации на `/batch/run`/`/batch/flush` (compute DoS) | Высокий | ✅ Закрыт (Bearer-token `QLSA_API_TOKEN`, constant-time, opt-in, 2026-06-10) |
| `setVerifier()` без timelock — single-key upgrade risk | Средний | Open (research prototype; рекомендуется 48h timelock + multisig для mainnet) |
| No authentication on `/batch/run` и `/batch/flush` — DoS через compute drain | Высокий | Open (rate limiting 20 ops/min; Bearer token рекомендуется для mainnet) |
| Off-chain mempool accepts stale-nonce transactions | Средний | Частично закрыто (2026-06-14): `ReplayedTxError` отклоняет re-submission уже забатченной tx в пределах retained history; полный per-sender nonce tracking рекомендуется для mainnet, on-chain registry — durable backstop |
| `POST /transactions` возвращал raw `str(exc)` (leak внутренних деталей валидации/ёмкости) | Низкий | ✅ Закрыто (fixed client-сообщения + server-side log, 2026-06-14) |
| Тест-фикстуры компилировались в production lib (`mod tests` без `#[cfg(test)]`) | Низкий | ✅ Закрыто (gate добавлен; release build warning-free, 2026-06-14) |

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
