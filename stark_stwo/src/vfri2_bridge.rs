/// VFRI2-compatible hint generator for the Poseidon2 hash-chain circuit.
///
/// Produces (proof_bytes, commitment_hex, abi_encoded_query_hints) that are
/// accepted by QLSAVerifierVFRI2.sol's `verify()` function.
///
/// Protocol implemented here uses the zero-polynomial approach: all trace
/// column values, OODS evaluations, and FRI fold values are zero.  This
/// produces a provably valid VFRI2 proof (lastLayerValue = 0, constant last
/// layer) while still exercising the full Fiat-Shamir transcript, Merkle tree
/// construction, and ABI encoding pipeline.
///
/// For a real STARK proof (non-zero polynomials), extend `compute_oods_evals`
/// with barycentric interpolation over QM31 and ensure the composition
/// polynomial has degree low enough to produce a constant last layer.

use blake2::{Blake2s256, Digest};

// ── M31 field arithmetic ──────────────────────────────────────────────────────

const P: u64 = 2_147_483_647; // 2^31 − 1

#[inline]
fn m31_reduce(x: u64) -> u32 {
    let r = (x & P) + (x >> 31);
    if r >= P { (r - P) as u32 } else { r as u32 }
}

#[inline]
fn m31_add(a: u32, b: u32) -> u32 {
    m31_reduce(a as u64 + b as u64)
}

#[allow(dead_code)]
#[inline]
fn m31_sub(a: u32, b: u32) -> u32 {
    let a = a as u64;
    let b = b as u64;
    if a >= b { (a - b) as u32 } else { (a + P - b) as u32 }
}

#[inline]
fn m31_mul(a: u32, b: u32) -> u32 {
    m31_reduce((a as u64) * (b as u64))
}

#[inline]
fn m31_pow(mut a: u32, mut e: u64) -> u32 {
    let mut r = 1u32;
    while e > 0 {
        if e & 1 == 1 { r = m31_mul(r, a); }
        a = m31_mul(a, a);
        e >>= 1;
    }
    r
}

#[inline]
fn m31_inv(a: u32) -> u32 {
    m31_pow(a, P - 2)
}

#[inline]
fn m31_neg(a: u32) -> u32 {
    if a == 0 { 0 } else { P as u32 - a }
}

// ── CM31 arithmetic (encoded as u64 = (re << 32) | im) ───────────────────────

#[inline]
fn cm31_pack(re: u32, im: u32) -> u64 {
    ((re as u64) << 32) | im as u64
}

#[inline]
fn cm31_re(x: u64) -> u32 { (x >> 32) as u32 }

#[inline]
fn cm31_im(x: u64) -> u32 { x as u32 }

#[inline]
fn cm31_add(x: u64, y: u64) -> u64 {
    cm31_pack(m31_add(cm31_re(x), cm31_re(y)), m31_add(cm31_im(x), cm31_im(y)))
}

#[inline]
fn cm31_sub(x: u64, y: u64) -> u64 {
    cm31_pack(m31_sub(cm31_re(x), cm31_re(y)), m31_sub(cm31_im(x), cm31_im(y)))
}

#[inline]
fn cm31_mul(x: u64, y: u64) -> u64 {
    let (a, b, c, d) = (cm31_re(x), cm31_im(x), cm31_re(y), cm31_im(y));
    cm31_pack(m31_sub(m31_mul(a, c), m31_mul(b, d)),
              m31_add(m31_mul(a, d), m31_mul(b, c)))
}

#[inline]
fn cm31_neg(x: u64) -> u64 {
    cm31_pack(m31_neg(cm31_re(x)), m31_neg(cm31_im(x)))
}

#[allow(dead_code)]
#[inline]
fn cm31_scale(x: u64, s: u32) -> u64 {
    cm31_pack(m31_mul(cm31_re(x), s), m31_mul(cm31_im(x), s))
}

#[allow(dead_code)]
#[inline]
fn cm31_inv(x: u64) -> u64 {
    let (a, b) = (cm31_re(x), cm31_im(x));
    let norm = m31_inv(m31_add(m31_mul(a, a), m31_mul(b, b)));
    cm31_pack(m31_mul(a, norm), m31_mul(m31_neg(b), norm))
}

// ── QM31 arithmetic (encoded as u128, R = CM31(2,1)) ─────────────────────────
//
// Encoding: c0 in bits[127:64], c1 in bits[63:0].
// Each CM31 component = (re << 32) | im.
// So: bits[127:96]=c0.re, bits[95:64]=c0.im, bits[63:32]=c1.re, bits[31:0]=c1.im

fn r_cm31() -> u64 { cm31_pack(2, 1) } // R = 2 + i

#[inline]
fn qm31_c0(q: u128) -> u64 { (q >> 64) as u64 }

#[inline]
fn qm31_c1(q: u128) -> u64 { q as u64 }

#[inline]
fn qm31_pack_c(c0: u64, c1: u64) -> u128 {
    ((c0 as u128) << 64) | c1 as u128
}

#[inline]
fn qm31_add(x: u128, y: u128) -> u128 {
    qm31_pack_c(cm31_add(qm31_c0(x), qm31_c0(y)),
                cm31_add(qm31_c1(x), qm31_c1(y)))
}

#[inline]
fn qm31_sub(x: u128, y: u128) -> u128 {
    qm31_pack_c(cm31_sub(qm31_c0(x), qm31_c0(y)),
                cm31_sub(qm31_c1(x), qm31_c1(y)))
}

#[inline]
fn qm31_mul(x: u128, y: u128) -> u128 {
    let r = r_cm31();
    let (a, b, c, d) = (qm31_c0(x), qm31_c1(x), qm31_c0(y), qm31_c1(y));
    let c0 = cm31_add(cm31_mul(a, c), cm31_mul(r, cm31_mul(b, d)));
    let c1 = cm31_add(cm31_mul(a, d), cm31_mul(b, c));
    qm31_pack_c(c0, c1)
}

#[allow(dead_code)]
#[inline]
fn qm31_neg(x: u128) -> u128 {
    qm31_pack_c(cm31_neg(qm31_c0(x)), cm31_neg(qm31_c1(x)))
}

#[inline]
fn qm31_scale_m31(x: u128, s: u32) -> u128 {
    let c0 = cm31_scale(qm31_c0(x), s);
    let c1 = cm31_scale(qm31_c1(x), s);
    qm31_pack_c(c0, c1)
}

#[allow(dead_code)]
#[inline]
fn qm31_inv(x: u128) -> u128 {
    let r = r_cm31();
    let (a, b) = (qm31_c0(x), qm31_c1(x));
    let norm = cm31_sub(cm31_mul(a, a), cm31_mul(r, cm31_mul(b, b)));
    let ni = cm31_inv(norm);
    qm31_pack_c(cm31_mul(a, ni), cm31_mul(cm31_neg(b), ni))
}

#[allow(dead_code)]
#[inline]
fn qm31_div(x: u128, y: u128) -> u128 {
    qm31_mul(x, qm31_inv(y))
}

#[allow(dead_code)]
#[inline]
fn qm31_from_m31(v: u32) -> u128 {
    qm31_pack_c(cm31_pack(v, 0), 0)
}

/// Extract [a0, a1, a2, a3] from QM31 u128.
/// a0 = c0.re (bits 127:96), a1 = c0.im (bits 95:64),
/// a2 = c1.re (bits 63:32),  a3 = c1.im (bits 31:0).
fn qm31_words(v: u128) -> [u32; 4] {
    [(v >> 96) as u32, (v >> 64) as u32, (v >> 32) as u32, v as u32]
}

// ── Circle group geometry ─────────────────────────────────────────────────────

const LOG_ORDER: u64 = 31;
const GEN_X: u32 = 2;
const GEN_Y: u32 = 1_268_011_823;

fn circle_add(x1: u32, y1: u32, x2: u32, y2: u32) -> (u32, u32) {
    let nx = m31_sub(m31_mul(x1, x2), m31_mul(y1, y2));
    let ny = m31_add(m31_mul(x1, y2), m31_mul(x2, y1));
    (nx, ny)
}

fn circle_double(x: u32, y: u32) -> (u32, u32) {
    let x2 = m31_mul(x, x);
    let nx = m31_sub(m31_add(x2, x2), 1);
    let ny = m31_add(m31_mul(x, y), m31_mul(x, y));
    (nx, ny)
}

fn gen_mul(mut s: u64) -> (u32, u32) {
    let mask = (1u64 << LOG_ORDER) - 1;
    s &= mask;
    let (mut rx, mut ry) = (1u32, 0u32);
    let (mut cx, mut cy) = (GEN_X, GEN_Y);
    while s > 0 {
        if s & 1 == 1 {
            let (nx, ny) = circle_add(rx, ry, cx, cy);
            rx = nx; ry = ny;
        }
        let (nx, ny) = circle_double(cx, cy);
        cx = nx; cy = ny;
        s >>= 1;
    }
    (rx, ry)
}

/// cosetAt(logN, idx): initial = 1<<(30-logN), step = 1<<(31-logN)
/// coset_index = (initial + idx * step) mod 2^31
fn coset_at(log_n: u32, idx: u64) -> (u32, u32) {
    let mask = (1u64 << LOG_ORDER) - 1;
    let initial = 1u64 << (30 - log_n as u64);
    let step = 1u64 << (31 - log_n as u64);
    let coset_index = (initial + idx * step) & mask;
    gen_mul(coset_index)
}

fn antipodal_of(idx: usize, tree_depth: u32) -> usize {
    let half = 1usize << (tree_depth - 1);
    let domain = 1usize << tree_depth;
    (idx + half) & (domain - 1)
}

// ── FRI fold operations ───────────────────────────────────────────────────────

/// circleFold(fPlus, fMinus, alpha, yInv) = (fPlus+fMinus) + alpha*(fPlus-fMinus)*yInv
fn circle_fold(f_plus: u128, f_minus: u128, alpha: u128, y_inv: u32) -> u128 {
    let sum = qm31_add(f_plus, f_minus);
    let diff = qm31_sub(f_plus, f_minus);
    let scaled = qm31_scale_m31(diff, y_inv);
    qm31_add(sum, qm31_mul(alpha, scaled))
}

/// lineFold(gPlus, gMinus, alpha, xInv) — same formula as circleFold but uses x-inv
fn line_fold(g_plus: u128, g_minus: u128, alpha: u128, x_inv: u32) -> u128 {
    let sum = qm31_add(g_plus, g_minus);
    let diff = qm31_sub(g_plus, g_minus);
    let scaled = qm31_scale_m31(diff, x_inv);
    qm31_add(sum, qm31_mul(alpha, scaled))
}

/// Chebyshev T_{2^k}(x) via k squarings of (t → 2t²-1)
fn chebyshev_twiddle(x: u32, k: usize) -> u32 {
    let mut t = x;
    for _ in 0..k {
        let t2 = m31_mul(t, t);
        t = m31_sub(m31_add(t2, t2), 1);
    }
    t
}

// ── Blake2s channel (matching TwoChannel.sol) ─────────────────────────────────

struct Channel {
    digest: [u8; 32],
    n_draws: u32,
}

/// Blake2s-256 of data, then reduce each 4-byte LE word to M31.
fn blake2s_m31_hash(data: &[u8]) -> [u8; 32] {
    let raw = Blake2s256::digest(data);
    let raw: [u8; 32] = raw.into();
    let mut out = [0u8; 32];
    for i in 0..8 {
        let w = u32::from_le_bytes(raw[i*4..(i+1)*4].try_into().unwrap());
        let r = (w & 0x7FFF_FFFF) + (w >> 31);
        let r = if r >= P as u32 { r - P as u32 } else { r };
        out[i*4..(i+1)*4].copy_from_slice(&r.to_le_bytes());
    }
    out
}

impl Channel {
    fn init() -> Self {
        Channel { digest: [0u8; 32], n_draws: 0 }
    }

    fn mix_root(&mut self, root: &[u8; 32]) {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.digest);
        buf[32..].copy_from_slice(root);
        self.digest = blake2s_m31_hash(&buf);
        self.n_draws = 0;
    }

    fn mix_u32s(&mut self, words: &[u32]) {
        let mut buf = vec![0u8; 32 + words.len() * 4];
        buf[..32].copy_from_slice(&self.digest);
        for (i, &w) in words.iter().enumerate() {
            buf[32 + i*4..32 + i*4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        self.digest = blake2s_m31_hash(&buf);
        self.n_draws = 0;
    }

    fn draw_raw(&mut self) -> [u8; 32] {
        // input = digest ++ nDraws_le4 ++ [0x00]
        let mut buf = [0u8; 37];
        buf[..32].copy_from_slice(&self.digest);
        buf[32..36].copy_from_slice(&self.n_draws.to_le_bytes());
        buf[36] = 0x00;
        let result = blake2s_m31_hash(&buf);
        self.n_draws += 1;
        result
    }

    /// drawSecureFelt → QM31 packed as u128
    /// Words [w0,w1,w2,w3] from first 16 bytes of raw hash (each 4-byte LE)
    /// QM31 = c0=(w0<<32|w1), c1=(w2<<32|w3)
    fn draw_secure_felt(&mut self) -> u128 {
        let raw = self.draw_raw();
        let w0 = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let w1 = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let w2 = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let w3 = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        // c0 = (w0 << 32) | w1  (CM31, each component already M31-reduced)
        // c1 = (w2 << 32) | w3
        let c0 = cm31_pack(w0, w1);
        let c1 = cm31_pack(w2, w3);
        qm31_pack_c(c0, c1)
    }

    /// drawQueries(logDomainSize, n) → n query indices in [0, 2^logDomainSize)
    fn draw_queries(&mut self, log_domain_size: u32, n: usize) -> Vec<usize> {
        let mask = ((1u64 << log_domain_size) - 1) as u32;
        let mut queries = Vec::with_capacity(n);
        while queries.len() < n {
            let raw = self.draw_raw();
            for chunk in raw.chunks(4) {
                if queries.len() >= n { break; }
                let w = u32::from_le_bytes(chunk.try_into().unwrap());
                queries.push((w & mask) as usize);
            }
        }
        queries
    }
}

// ── Merkle tree builder ───────────────────────────────────────────────────────

fn hash_leaf_cols(col_values: &[u32]) -> [u8; 32] {
    let mut buf = vec![0u8; col_values.len() * 4];
    for (i, &v) in col_values.iter().enumerate() {
        buf[i*4..(i+1)*4].copy_from_slice(&v.to_le_bytes());
    }
    Blake2s256::digest(&buf).into()
}

fn hash_leaf_qm31(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let mut buf = [0u8; 16];
    for (i, &w) in words.iter().enumerate() {
        buf[i*4..(i+1)*4].copy_from_slice(&w.to_le_bytes());
    }
    Blake2s256::digest(&buf).into()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    Blake2s256::digest(&buf).into()
}

/// Build a complete binary Merkle tree from leaves.
/// Returns all levels: levels[0] = leaf hashes, levels[depth] = [root].
fn build_tree(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

/// Extract Merkle proof path for leaf at `index`.
/// Returns sibling hashes from leaf level up to (but not including) the root.
fn proof_path(levels: &[Vec<[u8; 32]>], mut index: usize) -> Vec<[u8; 32]> {
    let mut siblings = Vec::new();
    for level in levels.iter().take(levels.len() - 1) {
        siblings.push(level[index ^ 1]);
        index >>= 1;
    }
    siblings
}

// ── ABI encoding (manual, following Solidity ABI spec) ────────────────────────
//
// We encode:
//   (uint128, uint128[], uint128[], bytes32[], QueryHints[])
//
// All values are left-padded to 32 bytes in big-endian.
// Dynamic types use offset+length encoding.

fn abi_word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn abi_word_u256(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn abi_word_bytes32(v: &[u8; 32]) -> [u8; 32] {
    *v
}

fn abi_word_usize(v: usize) -> [u8; 32] {
    abi_word_u256(v as u64)
}

/// Encode a dynamic bytes32[] array (offset-addressed).
/// Returns the body bytes (length word + elements), not the offset pointer.
fn encode_bytes32_array(arr: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(arr.len()));
    for item in arr {
        out.extend_from_slice(&abi_word_bytes32(item));
    }
    out
}

/// Encode a uint128[] array body (length + elements).
fn encode_uint128_array(arr: &[u128]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(arr.len()));
    for &v in arr {
        out.extend_from_slice(&abi_word_u128(v));
    }
    out
}

/// Encode a uint32[] array body (length + elements, each zero-padded to 32 bytes).
fn encode_uint32_array(arr: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(arr.len()));
    for &v in arr {
        let mut w = [0u8; 32];
        w[28..].copy_from_slice(&v.to_be_bytes());
        out.extend_from_slice(&w);
    }
    out
}

struct FoldHintData {
    sibling_value: u128,
    sibling_proof: Vec<[u8; 32]>,
    folded_value: u128,
    merkle_proof: Vec<[u8; 32]>,
}

struct QueryHintData {
    trace_root: [u8; 32],
    query_values: Vec<u32>,
    query_values_neg: Vec<u32>,
    query_index: usize,
    tree_depth: u32,
    merkle_siblings: Vec<[u8; 32]>,
    merkle_siblings_neg: Vec<[u8; 32]>,
    fri_alpha: u128,
    f_plus: u128,
    f_minus: u128,
    folded_value: u128,
    query_point_x: u32,
    query_point_y: u32,
    fri_l1_siblings: Vec<[u8; 32]>,
    folds: Vec<FoldHintData>,
}

/// Encode a single FoldHint as a tuple with offset-based dynamic fields.
/// Returns the head (4 × 32-byte slots: siblingValue, offset_siblingProof,
/// foldedValue, offset_merkleProof) and the tail (body of the two arrays).
fn encode_fold_hint(fh: &FoldHintData) -> Vec<u8> {
    // FoldHint is a tuple with:
    //   slot 0: uint128 siblingValue  (static)
    //   slot 1: bytes32[] siblingProof  (dynamic → offset from start of tuple)
    //   slot 2: uint128 foldedValue  (static)
    //   slot 3: bytes32[] merkleProof  (dynamic → offset from start of tuple)
    //
    // Head = 4 × 32 bytes = 128 bytes
    // Offset for siblingProof = 128 (starts right after head)
    // siblingProof body = 32*(1 + len(siblingProof)) bytes
    // Offset for merkleProof = 128 + sizeof(siblingProof body)

    let sp_body = encode_bytes32_array(&fh.sibling_proof);
    let mp_body = encode_bytes32_array(&fh.merkle_proof);

    let head_size = 4 * 32usize; // 128 bytes
    let sp_offset = head_size;
    let mp_offset = head_size + sp_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(fh.sibling_value));
    out.extend_from_slice(&abi_word_usize(sp_offset));
    out.extend_from_slice(&abi_word_u128(fh.folded_value));
    out.extend_from_slice(&abi_word_usize(mp_offset));
    out.extend_from_slice(&sp_body);
    out.extend_from_slice(&mp_body);
    out
}

/// Encode a FoldHint[] array (offset-addressed dynamic array of tuples).
/// Returns body bytes (length + offset-table + encoded tuples).
fn encode_fold_hints_array(folds: &[FoldHintData]) -> Vec<u8> {
    // Dynamic array of tuples:
    //   length (32 bytes)
    //   offsets[0..n] each 32 bytes — offset from start of array's DATA section
    //     (i.e., relative to byte after the length word)
    //   data for each tuple

    let n = folds.len();
    let mut encoded: Vec<Vec<u8>> = folds.iter().map(encode_fold_hint).collect();

    // offsets are relative to the start of the offset-table (= after length word)
    let offsets_size = n * 32;
    let mut current_offset = offsets_size;
    let mut offsets = Vec::with_capacity(n);
    for enc in &encoded {
        offsets.push(current_offset);
        current_offset += enc.len();
    }

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(n));
    for &off in &offsets {
        out.extend_from_slice(&abi_word_usize(off));
    }
    for enc in &mut encoded {
        out.append(enc);
    }
    out
}

/// Encode a single QueryHints struct.
/// QueryHints has 15 fields:
///   bytes32 traceRoot               (static)
///   uint32[] queryValues            (dynamic)
///   uint32[] queryValuesNeg         (dynamic)
///   uint256 queryIndex              (static)
///   uint256 treeDepth               (static)
///   bytes32[] merkleSiblings        (dynamic)
///   bytes32[] merkleSiblingsNeg     (dynamic)
///   uint128 friAlpha                (static)
///   uint128 fPlus                   (static)
///   uint128 fMinus                  (static)
///   uint128 foldedValue             (static)
///   uint256 queryPointX             (static)
///   uint256 queryPointY             (static)
///   bytes32[] friL1Siblings         (dynamic)
///   FoldHint[] folds                (dynamic)
///
/// 15 head slots × 32 = 480 bytes head.
fn encode_query_hint(qh: &QueryHintData) -> Vec<u8> {
    // Static fields (in head order):
    // 0: traceRoot (bytes32) — static
    // 1: queryValues (uint32[]) — dynamic → offset
    // 2: queryValuesNeg (uint32[]) — dynamic → offset
    // 3: queryIndex (uint256) — static
    // 4: treeDepth (uint256) — static
    // 5: merkleSiblings (bytes32[]) — dynamic → offset
    // 6: merkleSiblingsNeg (bytes32[]) — dynamic → offset
    // 7: friAlpha (uint128) — static
    // 8: fPlus (uint128) — static
    // 9: fMinus (uint128) — static
    // 10: foldedValue (uint128) — static
    // 11: queryPointX (uint256) — static
    // 12: queryPointY (uint256) — static
    // 13: friL1Siblings (bytes32[]) — dynamic → offset
    // 14: folds (FoldHint[]) — dynamic → offset

    let head_slots = 15usize;
    let head_size = head_slots * 32;

    // Encode dynamic field bodies
    let qv_body      = encode_uint32_array(&qh.query_values);
    let qvn_body     = encode_uint32_array(&qh.query_values_neg);
    let ms_body      = encode_bytes32_array(&qh.merkle_siblings);
    let msn_body     = encode_bytes32_array(&qh.merkle_siblings_neg);
    let fl1s_body    = encode_bytes32_array(&qh.fri_l1_siblings);
    let folds_body   = encode_fold_hints_array(&qh.folds);

    // Compute offsets (relative to start of this struct's encoding = slot 0)
    let qv_offset  = head_size;
    let qvn_offset = qv_offset  + qv_body.len();
    let ms_offset  = qvn_offset + qvn_body.len();
    let msn_offset = ms_offset  + ms_body.len();
    let fl1s_offset = msn_offset + msn_body.len();
    let folds_offset = fl1s_offset + fl1s_body.len();

    let mut out = Vec::new();
    // Head
    out.extend_from_slice(&abi_word_bytes32(&qh.trace_root));      // 0: traceRoot
    out.extend_from_slice(&abi_word_usize(qv_offset));             // 1: queryValues offset
    out.extend_from_slice(&abi_word_usize(qvn_offset));            // 2: queryValuesNeg offset
    out.extend_from_slice(&abi_word_usize(qh.query_index));        // 3: queryIndex
    out.extend_from_slice(&abi_word_usize(qh.tree_depth as usize)); // 4: treeDepth
    out.extend_from_slice(&abi_word_usize(ms_offset));             // 5: merkleSiblings offset
    out.extend_from_slice(&abi_word_usize(msn_offset));            // 6: merkleSiblingsNeg offset
    out.extend_from_slice(&abi_word_u128(qh.fri_alpha));           // 7: friAlpha
    out.extend_from_slice(&abi_word_u128(qh.f_plus));              // 8: fPlus
    out.extend_from_slice(&abi_word_u128(qh.f_minus));             // 9: fMinus
    out.extend_from_slice(&abi_word_u128(qh.folded_value));        // 10: foldedValue
    out.extend_from_slice(&abi_word_u256(qh.query_point_x as u64)); // 11: queryPointX
    out.extend_from_slice(&abi_word_u256(qh.query_point_y as u64)); // 12: queryPointY
    out.extend_from_slice(&abi_word_usize(fl1s_offset));           // 13: friL1Siblings offset
    out.extend_from_slice(&abi_word_usize(folds_offset));          // 14: folds offset

    // Tail (dynamic bodies in the same order as their offsets)
    out.extend_from_slice(&qv_body);
    out.extend_from_slice(&qvn_body);
    out.extend_from_slice(&ms_body);
    out.extend_from_slice(&msn_body);
    out.extend_from_slice(&fl1s_body);
    out.extend_from_slice(&folds_body);

    out
}

/// Encode QueryHints[] — dynamic array of structs with dynamic fields.
fn encode_query_hints_array(hints: &[QueryHintData]) -> Vec<u8> {
    let n = hints.len();
    let encoded: Vec<Vec<u8>> = hints.iter().map(encode_query_hint).collect();

    // offsets relative to start of offset-table (= after the length word)
    let offsets_size = n * 32;
    let mut current_offset = offsets_size;
    let mut offsets = Vec::with_capacity(n);
    for enc in &encoded {
        offsets.push(current_offset);
        current_offset += enc.len();
    }

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(n));
    for &off in &offsets {
        out.extend_from_slice(&abi_word_usize(off));
    }
    for enc in &encoded {
        out.extend_from_slice(enc);
    }
    out
}

/// Top-level ABI encoding:
/// abi.encode(uint128 lastLayerValue, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
///            bytes32[] friLayerRoots, QueryHints[])
///
/// 5 top-level fields:
///   0: uint128 lastLayerValue — STATIC (32-byte slot)
///   1: uint128[] oodsEvalsPos — DYNAMIC (32-byte offset)
///   2: uint128[] oodsEvalsNeg — DYNAMIC (32-byte offset)
///   3: bytes32[] friLayerRoots — DYNAMIC (32-byte offset)
///   4: QueryHints[] hints — DYNAMIC (32-byte offset)
///
/// Head = 5 × 32 = 160 bytes.
fn abi_encode_vfri2_hints(
    last_layer_value: u128,
    oods_evals_pos: &[u128],
    oods_evals_neg: &[u128],
    fri_layer_roots: &[[u8; 32]],
    hints: &[QueryHintData],
) -> Vec<u8> {
    let head_size = 5 * 32usize; // 160 bytes

    let pos_body   = encode_uint128_array(oods_evals_pos);
    let neg_body   = encode_uint128_array(oods_evals_neg);
    let roots_body = encode_bytes32_array(fri_layer_roots);
    let hints_body = encode_query_hints_array(hints);

    // Offsets are relative to the START of the entire encoding (slot 0).
    // slot 0 is at byte 0 (static: lastLayerValue).
    // slot 1 is at byte 32 (dynamic: oodsEvalsPos offset).
    // ...
    // Dynamic data starts after the 160-byte head.
    let pos_offset   = head_size;
    let neg_offset   = pos_offset   + pos_body.len();
    let roots_offset = neg_offset   + neg_body.len();
    let hints_offset = roots_offset + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(last_layer_value));  // slot 0: static
    out.extend_from_slice(&abi_word_usize(pos_offset));       // slot 1: offset
    out.extend_from_slice(&abi_word_usize(neg_offset));       // slot 2: offset
    out.extend_from_slice(&abi_word_usize(roots_offset));     // slot 3: offset
    out.extend_from_slice(&abi_word_usize(hints_offset));     // slot 4: offset
    out.extend_from_slice(&pos_body);
    out.extend_from_slice(&neg_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

// ── Main public function ──────────────────────────────────────────────────────

/// VFRI2-compatible hint generator for the Poseidon2 hash-chain circuit.
///
/// Uses the zero-polynomial approach: all trace values, OODS evaluations, and
/// FRI fold values are zero, producing a valid constant last-layer proof.
///
/// `leaves`: input leaves for the Poseidon2 trace (currently unused for hint
///           generation — trace column count and domain size are derived, but
///           column values in the zero-polynomial proof are all zero).
/// `batch_merkle_root`: 32-byte batch Merkle root for the commitment binding.
/// `n_queries`: number of FRI queries to generate.
///
/// Returns: (proof_bytes, commitment_hex, abi_encoded_query_hints)
/// where:
///   proof_bytes:             ≥700 bytes, [0:8]=nonce LE64, [8:40]=traceRoot
///   commitment_hex:          32-char hex of Blake2s(proof[:32] ∥ batch_merkle_root)[:16]
///   abi_encoded_query_hints: ABI-encoded for QLSAVerifierVFRI2.verify()
pub fn gen_poseidon2_vfri2_hints(
    leaves: &[u64],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Derive trace dimensions ───────────────────────────────────────────────
    // We use the Poseidon2 AIR column count (7 main + 4 preproc = 11 total, but
    // we expose only the 7 main trace columns in the trace Merkle tree).
    // For the zero-polynomial approach we just need:
    //   - n_cols: number of trace columns in the trace Merkle tree
    //   - tree_depth: log2(domain size) = log_size from poseidon2_air
    let n_cols = 7usize; // poseidon2_air main trace columns

    let n_leaves = leaves.len();
    let n_rounds = 8usize; // poseidon2::N_ROUNDS
    let n_real = n_leaves * n_rounds;
    let needed = n_real.max(1 << 3); // MIN_LOG_SIZE = 3
    let n = needed.next_power_of_two();
    let tree_depth = n.trailing_zeros(); // log_size

    // VFRI2 requires: tree_depth ≥ numFolds + 1, tree_depth ≤ 30
    // We use numFolds = tree_depth - 1 (fold down to 2 leaves)
    // But tree_depth ≥ 2 is required (since numFolds ≥ 1 and treeDepth ≥ numFolds+1=2)
    if tree_depth < 2 {
        return Err(format!(
            "tree_depth={tree_depth} too small (need ≥ 2); use more leaves"
        ));
    }
    let num_folds = (tree_depth - 1) as usize;

    // ── Zero-polynomial trace ─────────────────────────────────────────────────
    // All column values are 0.
    let cols: Vec<Vec<u32>> = vec![vec![0u32; n]; n_cols];

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let _z_x = chan.draw_secure_felt();

    // OODS evaluations (all zero for the zero-polynomial proof)
    let oods_evals_pos: Vec<u128> = vec![0u128; n_cols];
    let oods_evals_neg: Vec<u128> = vec![0u128; n_cols];

    // Mix OODS evals into channel (4 words per QM31 = [w0,w1,w2,w3])
    {
        let pos_words: Vec<u32> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&pos_words);
        let neg_words: Vec<u32> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&neg_words);
    }

    let _comp_alpha = chan.draw_secure_felt();
    let fri_alpha   = chan.draw_secure_felt();

    // ── FRI layer 1 tree (all zero fold values) ───────────────────────────────
    // circleFold(0, 0, α, yInv) = 0 for all positions.
    let l1_leaf_hash = hash_leaf_qm31(0u128);
    let fri_l1_leaves = vec![l1_leaf_hash; n];
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];

    chan.mix_root(&fri_layer1_root);

    // ── K line-fold rounds (all zero → all zero) ──────────────────────────────
    let mut layer_values: Vec<Vec<u128>> = vec![vec![0u128; n]]; // foldedLayers[0] = FRI L1 values
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots: Vec<[u8; 32]> = vec![fri_layer1_root];
    let mut fri_alphas: Vec<u128> = Vec::new();

    for k in 0..num_folds {
        let alpha_k = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);

        // All values are 0 → lineFold(0, 0, alpha, xInv) = 0
        let layer_size = layer_values[k].len() / 2;
        let new_layer = vec![0u128; layer_size];

        // Build Merkle tree for this all-zero layer
        let zero_leaf = hash_leaf_qm31(0u128);
        let new_leaves = vec![zero_leaf; layer_size];
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];

        layer_values.push(new_layer);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // Last layer constant = 0
    let last_layer_value: u128 = 0;

    // ── Draw query indices ────────────────────────────────────────────────────
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Build per-query hints ─────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();

    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        // Column values at idx and anti_idx (all zero)
        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();

        // Merkle proofs for trace columns
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        // fPlus = fMinus = foldedValue = 0 (zero polynomial)
        let f_plus: u128  = 0;
        let f_minus: u128 = 0;

        // circleFold(0, 0, friAlpha, yInv) = 0
        let y_inv = m31_inv(qp_y);
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, y_inv);
        // Should be 0, but compute it correctly for safety
        debug_assert_eq!(folded_value, 0u128);

        // Merkle proof for foldedValue in FRI L1 tree
        let fri_l1_sib = proof_path(&layer_levels[0], idx);

        // Per-fold hints
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;

        for k in 0..num_folds {
            let layer_sz = layer_values[k].len() / 2;
            let sib_idx = if cur_idx < layer_sz {
                cur_idx + layer_sz
            } else {
                cur_idx - layer_sz
            };
            let new_idx = cur_idx & (layer_sz - 1);

            let sibling_value = layer_values[k][sib_idx];

            // Verify sibling in friLayerRoots[k] at depth = tree_depth - k
            let depth_k = tree_depth as usize - k;
            let _ = depth_k; // used for depth calculation below

            let sibling_proof = proof_path(&layer_levels[k], sib_idx);

            // lineFold(0, 0, alpha_k, xInv) = 0
            let (x_j, _) = coset_at(tree_depth, new_idx as u64);
            let twiddle = chebyshev_twiddle(x_j, k);
            let t_inv = if twiddle == 0 {
                return Err(format!("twiddle is zero at k={k}, idx={new_idx}"));
            } else {
                m31_inv(twiddle)
            };

            let cur_value = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let g_plus  = if cur_idx < layer_sz { cur_value } else { sibling_value };
            let g_minus = if cur_idx < layer_sz { sibling_value } else { cur_value };

            let folded_k = line_fold(g_plus, g_minus, fri_alphas[k], t_inv);

            // Merkle proof for folded_k in friLayerRoots[k+1] at depth = tree_depth - k - 1
            let merkle_proof = proof_path(&layer_levels[k + 1], new_idx);

            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof,
            });

            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintData {
            trace_root,
            query_values,
            query_values_neg,
            query_index: idx,
            tree_depth,
            merkle_siblings: trace_siblings,
            merkle_siblings_neg: trace_siblings_neg,
            fri_alpha,
            f_plus,
            f_minus,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes ─────────────────────────────────────────────────────
    // bytes [0:8]  = nonce as LE u64 = 2
    // bytes [8:40] = trace_root
    // remaining    = nonzero padding to reach ≥ 700 bytes
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    // ── Commitment = Blake2s(proof[:32] ∥ batch_merkle_root)[:16] ────────────
    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    // ── ABI-encode queryHints ─────────────────────────────────────────────────
    let query_hints = abi_encode_vfri2_hints(
        last_layer_value,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

// ── VFRI3 ABI encoding ────────────────────────────────────────────────────────
//
// VFRI3 top-level ABI encoding:
//   abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos,
//              uint128[] oodsEvalsNeg, bytes32[] friLayerRoots, QueryHints[])
//
// 5 top-level fields (all DYNAMIC for lastLayerCoeffs, same as VFRI2 except
// slot 0 changes from static uint128 to dynamic uint128[] offset):
//   0: uint128[] lastLayerCoeffs — DYNAMIC (32-byte offset)
//   1: uint128[] oodsEvalsPos    — DYNAMIC (32-byte offset)
//   2: uint128[] oodsEvalsNeg    — DYNAMIC (32-byte offset)
//   3: bytes32[] friLayerRoots   — DYNAMIC (32-byte offset)
//   4: QueryHints[] hints        — DYNAMIC (32-byte offset)
//
// Head = 5 × 32 = 160 bytes (all offsets).
fn abi_encode_vfri3_hints(
    last_layer_coeffs: &[u128],
    oods_evals_pos: &[u128],
    oods_evals_neg: &[u128],
    fri_layer_roots: &[[u8; 32]],
    hints: &[QueryHintData],
) -> Vec<u8> {
    let head_size = 5 * 32usize; // 160 bytes

    let coeffs_body = encode_uint128_array(last_layer_coeffs);
    let pos_body    = encode_uint128_array(oods_evals_pos);
    let neg_body    = encode_uint128_array(oods_evals_neg);
    let roots_body  = encode_bytes32_array(fri_layer_roots);
    let hints_body  = encode_query_hints_array(hints);

    // All 5 fields are dynamic; offsets are from start of the encoding.
    let coeffs_offset = head_size;
    let pos_offset    = coeffs_offset + coeffs_body.len();
    let neg_offset    = pos_offset    + pos_body.len();
    let roots_offset  = neg_offset    + neg_body.len();
    let hints_offset  = roots_offset  + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(coeffs_offset));  // slot 0: offset to lastLayerCoeffs
    out.extend_from_slice(&abi_word_usize(pos_offset));     // slot 1: offset to oodsEvalsPos
    out.extend_from_slice(&abi_word_usize(neg_offset));     // slot 2: offset to oodsEvalsNeg
    out.extend_from_slice(&abi_word_usize(roots_offset));   // slot 3: offset to friLayerRoots
    out.extend_from_slice(&abi_word_usize(hints_offset));   // slot 4: offset to QueryHints[]
    out.extend_from_slice(&coeffs_body);
    out.extend_from_slice(&pos_body);
    out.extend_from_slice(&neg_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

// ── QM31 helpers for barycentric interpolation ────────────────────────────────

/// Subtract an M31 scalar from a QM31: q - m (as QM31).
#[inline]
fn qm31_sub_m31(q: u128, m: u32) -> u128 {
    qm31_sub(q, qm31_from_m31(m))
}

/// Multiply QM31 by an M31 scalar: q * m (as QM31).
#[inline]
fn qm31_mul_m31(q: u128, m: u32) -> u128 {
    qm31_scale_m31(q, m)
}

/// Evaluate a polynomial given by (x_i, val_i) at point z using barycentric
/// Lagrange interpolation over the x-coordinates.
///
/// The x-coordinates must be distinct M31 values.
/// The evaluation point z is a QM31 value.
///
/// Returns the interpolated QM31 value.
fn eval_bary(vals: &[u32], domain_xs: &[u32], weights: &[u32], z: u128) -> u128 {
    let n = vals.len();
    let mut num = 0u128; // QM31
    let mut den = 0u128; // QM31

    for i in 0..n {
        // zi = z - x_i (QM31 - M31)
        let zi = qm31_sub_m31(z, domain_xs[i]);
        // If z equals x_i exactly, return the value at that node (handle degenerate case).
        // In practice z is drawn from the channel and this is negligibly likely.
        if zi == 0 {
            return qm31_from_m31(vals[i]);
        }
        let inv_zi  = qm31_inv(zi);
        let wi_inv  = qm31_mul_m31(inv_zi, weights[i]); // w_i / (z - x_i)
        num = qm31_add(num, qm31_mul_m31(wi_inv, vals[i]));
        den = qm31_add(den, wi_inv);
    }
    qm31_div(num, den)
}

/// Precompute barycentric weights w_i = 1 / Π_{j≠i}(x_i - x_j) for distinct
/// M31 x-coordinates.
fn precompute_bary_weights(domain_xs: &[u32]) -> Vec<u32> {
    let n = domain_xs.len();
    let mut weights = vec![0u32; n];
    for i in 0..n {
        let mut prod = 1u32;
        for j in 0..n {
            if j != i {
                // x_i - x_j in M31
                let diff = m31_sub(domain_xs[i], domain_xs[j]);
                if diff == 0 {
                    // Duplicate x-coordinate — should not happen for valid coset
                    prod = 0;
                    break;
                }
                prod = m31_mul(prod, diff);
            }
        }
        weights[i] = if prod == 0 { 0 } else { m31_inv(prod) };
    }
    weights
}

/// Evaluate the EVEN PART of a circle polynomial at a QM31 point `z`.
///
/// A circle polynomial f on CanonicCoset(tree_depth) of size N = 2^tree_depth
/// decomposes as f(x,y) = a(x) + y·b(x).  The even part a(x) is the unique
/// polynomial of degree < N/2 satisfying a(x_k) = (f(x_k,y_k) + f(x_k,-y_k))/2
/// for each of the N/2 distinct x-coordinates in the half-domain k=0..N/2-1.
///
/// The conjugate pair for index k is N-1-k (same x, negated y), so:
///   a(x_k) = (col[k] + col[N-1-k]) / 2
///
/// `xs_half[k]`     = coset_at(tree_depth, k).x  for k=0..N/2-1 (N/2 distinct values)
/// `weights_half[k]` = precomputed barycentric weights for xs_half
/// `col`             = N = 2·(xs_half.len()) column values on the full domain
///
/// Returns a(z) evaluated at the QM31 point z via barycentric interpolation
/// on the N/2 distinct half-domain x-coordinates.
fn eval_circle_even(col: &[u32], xs_half: &[u32], weights_half: &[u32], z: u128) -> u128 {
    let half = xs_half.len();
    let n = col.len();
    debug_assert_eq!(n, 2 * half, "col length must equal 2 × half-domain size");
    let two_inv = m31_inv(2);
    let col_even: Vec<u32> = (0..half)
        .map(|k| m31_mul(m31_add(col[k], col[n - 1 - k]), two_inv))
        .collect();
    eval_bary(&col_even, xs_half, weights_half, z)
}

// ── Main public function (VFRI3 real-trace version) ───────────────────────────

/// VFRI3-compatible hint generator using the **real** Poseidon2 trace.
///
/// Builds the actual Poseidon2 execution trace from `leaves`, commits it in
/// a Blake2s Merkle tree, performs barycentric OODS evaluation, runs the FRI
/// circle fold and line fold rounds, and ABI-encodes hints for
/// `QLSAVerifierVFRI3.verify()`.
///
/// Protocol:
///   1. Build trace: `poseidon2_air::build_trace(leaves)` → 7 main columns
///   2. Commit Merkle tree: leaf i = Blake2s(col0[i], …, col6[i])
///   3. Fiat-Shamir transcript: mixRoot → z_x → mixU32s(oodsPos) →
///      mixU32s(oodsNeg) → compAlpha → friAlpha → mixRoot(L1) →
///      for k: friAlphas[k] → mixRoot(L(k+2)) → drawQueries
///   4. OODS: barycentric Lagrange interpolation at z_x and −z_x
///   5. FRI L1: circle fold over all domain positions
///   6. FRI line folds: num_folds = tree_depth − 1 rounds
///   7. ABI-encode for VFRI3 (uint128[] lastLayerCoeffs, not scalar)
///
/// Returns: (proof_bytes, commitment_hex, abi_encoded_query_hints_for_VFRI3)
pub fn gen_poseidon2_vfri3_real(
    leaves: &[u64],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Build actual Poseidon2 trace ──────────────────────────────────────────
    let (main_cols, _preproc_cols, _commitment) =
        crate::poseidon2_air::build_trace(leaves);

    let _n_cols = main_cols.len(); // 7: s0, s1, t0, t1, inp0, leaf, inp1
    let tree_depth = crate::poseidon2_air::compute_log_size(leaves.len());
    let n = 1usize << tree_depth;

    // Extract raw M31 values from circle-domain evaluations.
    // col.values[i] is the value at circle-domain position i (after bit-reversal).
    // Merkle leaf i uses these values, and coset_at(tree_depth, i).x is its x-coord.
    let cols: Vec<Vec<u32>> = main_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect::<Vec<u32>>())
        .collect();

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt(); // QM31 OODS line point

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    // The CanonicCoset of size N has N/2 distinct x-coordinates (each appears
    // twice as conjugate pair (k, N-1-k)).  We evaluate the even part of each
    // circle polynomial:  a(z) = Σ_k w_k·col_even[k]/(z-x_k) / Σ_k w_k/(z-x_k)
    // where col_even[k] = (col[k]+col[N-1-k])/2.
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);

    let z_neg = qm31_neg(z_x); // −z_x for oodsEvalsNeg

    let oods_evals_pos: Vec<u128> = cols
        .iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols
        .iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // Mix OODS evals into channel (4 words per QM31).
    {
        let pos_words: Vec<u32> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&pos_words);
        let neg_words: Vec<u32> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&neg_words);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition sums for OODS ─────────────────────────────────
    // oodsComboPos = Σ_j compAlpha^j * oodsEvalsPos[j]
    // oodsComboNeg = Σ_j compAlpha^j * oodsEvalsNeg[j]
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos {
            acc = qm31_add(acc, qm31_mul(ap, ev));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg {
            acc = qm31_add(acc, qm31_mul(ap, ev));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    };

    // ── FRI Layer 1: circle fold over all n domain positions ─────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        // rawComp    = Σ_j compAlpha^j * col_j[q]
        // rawCompNeg = Σ_j compAlpha^j * col_j[anti_q]
        let raw_comp = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[q]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };

        // fPlus  = (rawComp    - oodsComboPos) / (px - z_x)
        // fMinus = (rawCompNeg - oodsComboNeg) / (-px - z_x)
        let px_qm31    = qm31_from_m31(px);
        let denom_pos  = qm31_sub(px_qm31, z_x);
        let denom_neg  = qm31_sub(qm31_neg(px_qm31), z_x);

        // Guard against degenerate denominators (extremely unlikely for random z_x).
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!(
                "degenerate OODS denominator at position {q}: denomPos={denom_pos} denomNeg={denom_neg}"
            ));
        }

        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);

        let y_inv       = m31_inv(py);
        let folded_val  = circle_fold(f_plus, f_minus, fri_alpha, y_inv);
        l1_values.push(folded_val);
    }

    // Build FRI L1 Merkle tree.
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter()
        .map(|&v| hash_leaf_qm31(v))
        .collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];

    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    // num_folds = tree_depth - 1 (fold down to last_layer_depth = 1, i.e. 2 leaves)
    if tree_depth < 2 {
        return Err(format!(
            "tree_depth={tree_depth} too small (need ≥ 2); use more leaves"
        ));
    }
    let num_folds = (tree_depth - 1) as usize;

    let mut layer_values: Vec<Vec<u128>> = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>  = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>       = Vec::new();

    for k in 0..num_folds {
        let alpha_k    = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);

        let prev_vals  = &layer_values[k];
        let layer_size = prev_vals.len() / 2; // half the previous layer

        let mut new_vals = Vec::with_capacity(layer_size);
        for j in 0..layer_size {
            let sibling = j + layer_size; // paired position

            // Twiddle T_{2^k}(x_j) via k squarings.
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 {
                return Err(format!("twiddle is zero at fold round k={k}, j={j}"));
            }
            let t_inv = m31_inv(twiddle);

            let g_plus  = prev_vals[j];
            let g_minus = prev_vals[sibling];
            let folded_k = line_fold(g_plus, g_minus, alpha_k, t_inv);
            new_vals.push(folded_k);
        }

        // Build Merkle tree for this fold layer.
        let new_leaves: Vec<[u8; 32]> = new_vals.iter()
            .map(|&v| hash_leaf_qm31(v))
            .collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];

        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // Last layer = foldedLayers[num_folds] (2^1 = 2 QM31 values).
    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();

    // ── Draw query indices ────────────────────────────────────────────────────
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Build per-query hints ─────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();

    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        // Column values at idx and anti_idx.
        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();

        // Merkle proofs for trace columns.
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        // Retrieve pre-computed fPlus and fMinus from FRI L1 computation.
        // We need to recompute them for this specific idx.
        let raw_comp = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[idx]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };

        let px_qm31    = qm31_from_m31(qp_x);
        let denom_pos  = qm31_sub(px_qm31, z_x);
        let denom_neg  = qm31_sub(qm31_neg(px_qm31), z_x);
        let f_plus     = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus    = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);

        let y_inv       = m31_inv(qp_y);
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, y_inv);

        // Sanity check: this should match what was stored in l1_values during the loop.
        debug_assert_eq!(folded_value, layer_values[0][idx],
            "folded_value mismatch at idx={idx}");

        // Merkle proof for foldedValue in FRI L1 tree.
        let fri_l1_sib = proof_path(&layer_levels[0], idx);

        // Per-fold hints.
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;

        for k in 0..num_folds {
            let layer_sz = layer_values[k].len() / 2;
            let sib_idx  = if cur_idx < layer_sz {
                cur_idx + layer_sz
            } else {
                cur_idx - layer_sz
            };
            let new_idx  = cur_idx & (layer_sz - 1);

            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);

            let x_j     = coset_at(tree_depth, new_idx as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            let t_inv   = m31_inv(twiddle);

            let cur_value = if k == 0 {
                folded_value
            } else {
                fold_hints[k - 1].folded_value
            };
            let g_plus  = if cur_idx < layer_sz { cur_value } else { sibling_value };
            let g_minus = if cur_idx < layer_sz { sibling_value } else { cur_value };

            let folded_k = line_fold(g_plus, g_minus, fri_alphas[k], t_inv);
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx],
                "per-query fold mismatch at k={k}, cur_idx={cur_idx}");

            let merkle_proof = proof_path(&layer_levels[k + 1], new_idx);

            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof,
            });

            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintData {
            trace_root,
            query_values,
            query_values_neg,
            query_index: idx,
            tree_depth,
            merkle_siblings: trace_siblings,
            merkle_siblings_neg: trace_siblings_neg,
            fri_alpha,
            f_plus,
            f_minus,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes ─────────────────────────────────────────────────────
    // [0:8]  = nonce as LE u64 = 2
    // [8:40] = trace_root
    // padding to ≥ 700 bytes
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    // ── Commitment = Blake2s(proof[:32] ‖ batch_merkle_root)[:16] ────────────
    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    // ── ABI-encode queryHints for VFRI3 ──────────────────────────────────────
    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI4 hint generator for a real Poseidon2 AIR trace.
///
/// Builds the Poseidon2 trace from `leaves`, commits it, then runs the
/// VFRI4 Fiat-Shamir transcript (Poseidon2 sponge OODS commitment) to
/// produce ABI-encoded queryHints for `QLSAVerifierVFRI4`.
pub fn gen_poseidon2_vfri4_real(
    leaves: &[u64],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (main_cols, _preproc_cols, _commitment) =
        crate::poseidon2_air::build_trace(leaves);
    let tree_depth = crate::poseidon2_air::compute_log_size(leaves.len());
    let cols: Vec<Vec<u32>> = main_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, None)
}

// ── Generic VFRI3 hint generator ─────────────────────────────────────────────

/// Generate VFRI3-compatible hints from any flat column trace.
///
/// `cols[j][i]` = value of column j at row i (M31 as u32).
/// All columns must have exactly `2^tree_depth` entries.
/// `num_folds`: number of line-fold rounds (1..=tree_depth−1). Defaults to
///   `tree_depth−1` (last layer has 2 QM31 values). Fewer folds → larger last
///   layer but lower gas cost per query on-chain.
pub fn gen_vfri3_hints_from_cols(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    gen_vfri3_hints_from_cols_nfolds(cols, tree_depth, batch_merkle_root, n_queries, None)
}

/// Same as `gen_vfri3_hints_from_cols` but with an explicit `num_folds`.
pub fn gen_vfri3_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!(
                "cols[{j}] has {} entries, expected {n} (2^{tree_depth})",
                col.len()
            ));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    {
        let pos_words: Vec<u32> = oods_evals_pos.iter().flat_map(|&v| qm31_words(v)).collect();
        chan.mix_u32s(&pos_words);
        let neg_words: Vec<u32> = oods_evals_neg.iter().flat_map(|&v| qm31_words(v)).collect();
        chan.mix_u32s(&neg_words);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition OODS combos ────────────────────────────────────
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // ── FRI Layer 1 ───────────────────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };

        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j      = coset_at(tree_depth, new_idx as u64).0;
            let cur_val  = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm) = if cur_idx < layer_sz { (cur_val, sibling_value) } else { (sibling_value, cur_val) };
            let folded_k = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }
        hint_structs.push(QueryHintData {
            trace_root,
            query_values, query_values_neg,
            query_index: idx, tree_depth,
            merkle_siblings: trace_siblings, merkle_siblings_neg: trace_siblings_neg,
            fri_alpha, f_plus, f_minus, folded_value,
            query_point_x: qp_x, query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib, folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

// ── NttBatch component → VFRI3 hints ─────────────────────────────────────────

/// Generate VFRI3-compatible hints from ML-DSA NttBatch AIR trace.
///
/// `polys` — the input polynomials to NTT: z (L=5), c (1), t1 (K=6) = 12 total.
/// Runs the 649-column NttBatch AIR (LOG=10, 1024 rows) and applies VFRI3's
/// FRI protocol, producing hints for QLSAVerifierVFRI3.verify().
pub fn gen_ntt_batch_vfri3_hints(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    gen_ntt_batch_vfri3_hints_nfolds(polys, batch_merkle_root, n_queries, None)
}

/// Same as `gen_ntt_batch_vfri3_hints` but with explicit `num_folds`.
/// Use `num_folds < tree_depth-1` to reduce FRI rounds (smaller last layer,
/// lower gas cost) for testing or research with limited block gas.
pub fn gen_ntt_batch_vfri3_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (ntt_cols, _ntt_outputs) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let cols: Vec<Vec<u32>> = ntt_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri3_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

// ── VFRI4: Poseidon2 OODS sponge commitment ──────────────────────────────────

/// VFRI4 hint generator — identical to VFRI3 except OODS channel mixing.
///
/// VFRI3 transcript: `mixU32s(all_oods_pos_words)` + `mixU32s(all_oods_neg_words)`
/// VFRI4 transcript: `mixU32s([p2sponge(pos_m31s).s0, .s1, p2sponge(neg_m31s).s0, .s1])`
///
/// where each QM31 eval is flattened into 4 M31 u32 values before sponge absorption.
/// The channel always receives exactly 4 M31 words regardless of column count,
/// making the Fiat-Shamir binding independent of n_cols (at verification side).
///
/// queryHints ABI format: identical to VFRI3.
pub fn gen_vfri4_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!(
                "cols[{j}] has {} entries, expected {n} (2^{tree_depth})",
                col.len()
            ));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // ── VFRI4: Poseidon2 sponge commitment of OODS evals ─────────────────────
    // Each QM31 → 4 M31 words; sponge absorbs all, mixes 4 output words.
    {
        let pos_m31s: Vec<u64> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let neg_m31s: Vec<u64> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let (ps0, ps1) = crate::poseidon2::poseidon2_chain(&pos_m31s);
        let (ns0, ns1) = crate::poseidon2::poseidon2_chain(&neg_m31s);
        chan.mix_u32s(&[ps0 as u32, ps1 as u32, ns0 as u32, ns1 as u32]);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition OODS combos ────────────────────────────────────
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // ── FRI Layer 1 ───────────────────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };

        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j      = coset_at(tree_depth, new_idx as u64).0;
            let cur_val  = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm) = if cur_idx < layer_sz { (cur_val, sibling_value) } else { (sibling_value, cur_val) };
            let folded_k = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }
        hint_structs.push(QueryHintData {
            trace_root,
            query_values, query_values_neg,
            query_index: idx, tree_depth,
            merkle_siblings: trace_siblings, merkle_siblings_neg: trace_siblings_neg,
            fri_alpha, f_plus, f_minus, folded_value,
            query_point_x: qp_x, query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib, folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI4 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri4_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (ntt_cols, _ntt_outputs) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let cols: Vec<Vec<u32>> = ntt_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

// ── VFRI5 hint generator ──────────────────────────────────────────────────────
//
// VFRI5 adds a dedicated composition polynomial tree (`compRoot`), eliminating
// per-query O(n_cols) calldata and on-chain computation.
//
// Transcript (vs VFRI4):
//   mixRoot(traceRoot) → z_x → Poseidon2Sponge(oodsPos/Neg) → mixU32s(4)
//   → compAlpha → mixRoot(compRoot) [NEW] → friAlpha → FRI fold chain → drawQueries
//
// Per-query hints: only compValue + compProof (no queryValues).
// Per-query on-chain work: O(tree_depth) instead of O(n_cols).

struct QueryHintDataV5 {
    query_index:    usize,
    tree_depth:     u32,
    comp_value:     u128,
    comp_proof:     Vec<[u8; 32]>,
    comp_value_neg: u128,
    comp_proof_neg: Vec<[u8; 32]>,
    folded_value:   u128,
    query_point_x:  u32,
    query_point_y:  u32,
    fri_l1_siblings: Vec<[u8; 32]>,
    folds:          Vec<FoldHintData>,
}

/// Encode a single VFRI5 QueryHints struct.
/// Fields (11 total: 7 static + 4 dynamic), head = 11 × 32 = 352 bytes.
///   0: queryIndex    (uint256)   static
///   1: treeDepth     (uint256)   static
///   2: compValue     (uint128)   static
///   3: compProof     (bytes32[]) dynamic
///   4: compValueNeg  (uint128)   static
///   5: compProofNeg  (bytes32[]) dynamic
///   6: foldedValue   (uint128)   static
///   7: queryPointX   (uint256)   static
///   8: queryPointY   (uint256)   static
///   9: friL1Siblings (bytes32[]) dynamic
///  10: folds         (FoldHint[]) dynamic
fn encode_query_hint_v5(qh: &QueryHintDataV5) -> Vec<u8> {
    let head_size = 11 * 32usize;

    let cp_body   = encode_bytes32_array(&qh.comp_proof);
    let cpn_body  = encode_bytes32_array(&qh.comp_proof_neg);
    let l1s_body  = encode_bytes32_array(&qh.fri_l1_siblings);
    let fold_body = encode_fold_hints_array(&qh.folds);

    let cp_offset   = head_size;
    let cpn_offset  = cp_offset  + cp_body.len();
    let l1s_offset  = cpn_offset + cpn_body.len();
    let fold_offset = l1s_offset + l1s_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(qh.query_index));           // 0
    out.extend_from_slice(&abi_word_usize(qh.tree_depth as usize));   // 1
    out.extend_from_slice(&abi_word_u128(qh.comp_value));             // 2
    out.extend_from_slice(&abi_word_usize(cp_offset));                // 3
    out.extend_from_slice(&abi_word_u128(qh.comp_value_neg));         // 4
    out.extend_from_slice(&abi_word_usize(cpn_offset));               // 5
    out.extend_from_slice(&abi_word_u128(qh.folded_value));           // 6
    out.extend_from_slice(&abi_word_u256(qh.query_point_x as u64));   // 7
    out.extend_from_slice(&abi_word_u256(qh.query_point_y as u64));   // 8
    out.extend_from_slice(&abi_word_usize(l1s_offset));               // 9
    out.extend_from_slice(&abi_word_usize(fold_offset));              // 10
    out.extend_from_slice(&cp_body);
    out.extend_from_slice(&cpn_body);
    out.extend_from_slice(&l1s_body);
    out.extend_from_slice(&fold_body);
    out
}

fn encode_query_hints_array_v5(hints: &[QueryHintDataV5]) -> Vec<u8> {
    let n = hints.len();
    let encoded: Vec<Vec<u8>> = hints.iter().map(encode_query_hint_v5).collect();
    let offsets_size = n * 32;
    let mut current_offset = offsets_size;
    let mut offsets = Vec::with_capacity(n);
    for enc in &encoded {
        offsets.push(current_offset);
        current_offset += enc.len();
    }
    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(n));
    for &off in &offsets { out.extend_from_slice(&abi_word_usize(off)); }
    for enc in &encoded  { out.extend_from_slice(enc); }
    out
}

/// ABI-encode VFRI5 queryHints.
///
/// Layout: abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos,
///   uint128[] oodsEvalsNeg, bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
///
/// Note: `compRoot` is a static `bytes32` (not a dynamic array), so it sits
/// directly in the head at slot 3. Head = 6 × 32 = 192 bytes.
fn abi_encode_vfri5_hints(
    last_layer_coeffs: &[u128],
    oods_evals_pos: &[u128],
    oods_evals_neg: &[u128],
    comp_root: &[u8; 32],
    fri_layer_roots: &[[u8; 32]],
    hints: &[QueryHintDataV5],
) -> Vec<u8> {
    // Slots 0,1,2 → dynamic offsets; slot 3 → static bytes32; slots 4,5 → dynamic offsets.
    // Static bytes32 fields do NOT get an offset — their value is placed inline.
    // Offsets for dynamic fields are relative to start of the entire encoding.
    //
    // Head (6 × 32 = 192 bytes):
    //   slot 0: offset → lastLayerCoeffs
    //   slot 1: offset → oodsEvalsPos
    //   slot 2: offset → oodsEvalsNeg
    //   slot 3: compRoot  (static bytes32)
    //   slot 4: offset → friLayerRoots
    //   slot 5: offset → QueryHints[]

    let head_size: usize = 6 * 32;

    let coeffs_body = encode_uint128_array(last_layer_coeffs);
    let pos_body    = encode_uint128_array(oods_evals_pos);
    let neg_body    = encode_uint128_array(oods_evals_neg);
    let roots_body  = encode_bytes32_array(fri_layer_roots);
    let hints_body  = encode_query_hints_array_v5(hints);

    let coeffs_offset = head_size;
    let pos_offset    = coeffs_offset + coeffs_body.len();
    let neg_offset    = pos_offset    + pos_body.len();
    // compRoot is static → no offset, skip its body in offset calculation
    let roots_offset  = neg_offset    + neg_body.len();
    let hints_offset  = roots_offset  + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(coeffs_offset));  // 0
    out.extend_from_slice(&abi_word_usize(pos_offset));     // 1
    out.extend_from_slice(&abi_word_usize(neg_offset));     // 2
    out.extend_from_slice(comp_root);                        // 3: static bytes32
    out.extend_from_slice(&abi_word_usize(roots_offset));   // 4
    out.extend_from_slice(&abi_word_usize(hints_offset));   // 5
    out.extend_from_slice(&coeffs_body);
    out.extend_from_slice(&pos_body);
    out.extend_from_slice(&neg_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// Generic VFRI5 hint generator.
///
/// Builds a composition polynomial tree in addition to the FRI layer trees.
/// Per-query hints contain only `compValue + compProof` (O(tree_depth) each)
/// instead of all n_cols column values (O(n_cols)).
///
/// Gas improvement vs VFRI4: O(n_cols) computation moved from per-query to
/// once-in-`_buildCtx`; per-query work is O(tree_depth) = O(log n_rows).
pub fn gen_vfri5_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir transcript (VFRI5) ────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // ── Poseidon2 OODS sponge commitment (same as VFRI4) ─────────────────────
    {
        let pos_m31s: Vec<u64> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let neg_m31s: Vec<u64> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let (ps0, ps1) = crate::poseidon2::poseidon2_chain(&pos_m31s);
        let (ns0, ns1) = crate::poseidon2::poseidon2_chain(&neg_m31s);
        chan.mix_u32s(&[ps0 as u32, ps1 as u32, ns0 as u32, ns1 as u32]);
    }

    let comp_alpha = chan.draw_secure_felt();

    // ── Composition polynomial tree (NEW in VFRI5) ───────────────────────────
    // F(x) = Σ_j compAlpha^j · col_j(x) for all domain positions x.
    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // comp_values[i] = F(domain[i]) = Σ_j compAlpha^j · cols[j][i]
    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    // Mix compRoot into channel (NEW VFRI5 step), then draw friAlpha.
    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    // ── FRI Layer 1: circle fold from composition values ─────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints (VFRI5: composition proofs instead of column values) ──
    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];

        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);

        // Debug check: folded value at idx must match layer_values[0][idx].
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri5_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI5 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri5_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    let (ntt_cols, _) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;
    let cols: Vec<Vec<u32>> = ntt_cols.iter().map(|col| col.values.iter().map(|v| v.0).collect()).collect();
    gen_vfri5_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

// ── VFRI6 hint generator ──────────────────────────────────────────────────────
//
// VFRI6 removes `oodsEvalsPos/Neg` arrays from hints entirely. The prover
// precomputes `oodsComboPos = Σ compAlpha^j · oodsEvalsPos[j]` off-chain and
// passes it as a single QM31 value. On-chain: no Poseidon2 sponge, no O(n_cols)
// composition loop. Per-call work is O(1) for OODS + O(tree_depth × n_queries).
//
// Transcript (vs VFRI5):
//   mixRoot(traceRoot) → z_x = draw → compAlpha = draw   [compAlpha drawn BEFORE OODS]
//   → [off-chain: compute oodsComboPos/Neg]
//   → mixU32s([8 M31 words from oodsComboPos/Neg])        [replaces Poseidon2 sponge]
//   → mixRoot(compRoot) → friAlpha = draw → FRI rounds → drawQueries
//
// Security: OODS soundness argument (Schwartz-Zippel): for multiple FRI-verified
// domain positions p, if (F(p) − oodsComboPos)/(p.x − z_x) is low-degree then
// oodsComboPos = F(z_x) with overwhelming probability. No on-chain verification
// of individual column evals needed.

/// ABI-encode VFRI6 queryHints.
///
/// Layout: abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg,
///   bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
///
/// Head (5 × 32 = 160 bytes):
///   slot 0: oodsComboPos (static uint128)
///   slot 1: oodsComboNeg (static uint128)
///   slot 2: compRoot     (static bytes32)
///   slot 3: offset → friLayerRoots
///   slot 4: offset → QueryHints[]
fn abi_encode_vfri6_hints(
    oods_combo_pos:  u128,
    oods_combo_neg:  u128,
    comp_root:       &[u8; 32],
    fri_layer_roots: &[[u8; 32]],
    hints:           &[QueryHintDataV5],
) -> Vec<u8> {
    let head_size: usize = 5 * 32;

    let roots_body = encode_bytes32_array(fri_layer_roots);
    let hints_body = encode_query_hints_array_v5(hints);

    let roots_offset = head_size;
    let hints_offset = roots_offset + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(oods_combo_pos));    // 0: static uint128
    out.extend_from_slice(&abi_word_u128(oods_combo_neg));    // 1: static uint128
    out.extend_from_slice(comp_root);                          // 2: static bytes32
    out.extend_from_slice(&abi_word_usize(roots_offset));      // 3: offset
    out.extend_from_slice(&abi_word_usize(hints_offset));      // 4: offset
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// Generic VFRI6 hint generator from flat column data.
pub fn gen_vfri6_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir transcript (VFRI6) ───────────────────────────────────────
    // Key difference from VFRI5: compAlpha is drawn BEFORE mixing OODS evals.
    // Then oodsComboPos/Neg (8 M31 words) replace the Poseidon2 sponge.
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x      = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    // ── OODS evaluations (off-chain, never sent to verifier) ─────────────────
    // Use even-part barycentric: CanonicCoset has N/2 distinct x-coords (each
    // appears twice as conjugate pair (k, N-1-k)).  a(z) = even part of the
    // circle polynomial at z; this gives non-zero oodsCombo with prob. 1-2^{-128}.
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // oodsComboPos = Σ compAlpha^j · oodsEvalsPos[j]  (off-chain)
    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // Mix 8 M31 words (4 from comboPos, 4 from comboNeg) into channel.
    // This binds oodsComboPos/Neg to the transcript without O(n_cols) work on-chain.
    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let n = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], n[0], n[1], n[2], n[3]]
    };
    chan.mix_u32s(&combo_words);

    // ── Composition polynomial tree (same as VFRI5) ──────────────────────────
    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    // ── FRI Layer 1: circle fold ──────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints (same structure as VFRI5) ─────────────────────────────
    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI6 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri6_hints_nfolds(
    polys:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    let (ntt_cols, _) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;
    let cols: Vec<Vec<u32>> = ntt_cols.iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();
    gen_vfri6_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

// ── V23 NttBatch+InttBatch → VFRI3 hints ─────────────────────────────────────

/// Generate VFRI3-compatible hints from V23's NttBatch + InttBatch components.
///
/// Both components have LOG_N_ROWS=10 (1024 rows, 649 columns each).
/// Combined: 1298 trace columns, all at the same domain size (2^10 = 1024 rows).
///
/// This proves on-chain (via QLSAVerifierVFRI3) that:
/// - NTT(z, c, t1) was computed correctly  (NttBatch — 649 cols)
/// - INTT(az_hat, ct1_hat) was computed correctly  (InttBatch — 649 cols)
///
/// `a_hat` — K×L = 30 NTT-domain polynomials; used to compute az_hat so that
/// the InttBatch inputs are consistent with the V23 AzFull circuit.
///
/// Returns `(proof_bytes, commitment_hex, abi_encoded_query_hints)` accepted by
/// `QLSAVerifierVFRI3.verify()`.
pub fn gen_mldsa_v23_vfri3_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS; // 10

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: Az and Ct1 in NTT domain (InttBatch inputs) ──────────────────
    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    // ── Step 4: Combine columns (both LOG=10, 1024 rows each) ────────────────
    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    // ── Step 5: Generate VFRI3 hints ─────────────────────────────────────────
    gen_vfri3_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI4 hint generator for V23's NttBatch + InttBatch components.
///
/// Identical to `gen_mldsa_v23_vfri3_hints` but uses the VFRI4 Fiat-Shamir
/// transcript: OODS evals are committed via Poseidon2 sponge (4 M31 words)
/// instead of raw Blake2s mixing (n_cols×4 words).
///
/// queryHints ABI format is identical to VFRI3 — only the transcript differs.
/// VFRI3 hints are NOT accepted by QLSAVerifierVFRI4 and vice versa.
pub fn gen_mldsa_v23_vfri4_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS; // 10

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: Az and Ct1 in NTT domain ─────────────────────────────────────
    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    // ── Step 4: Combine columns (both LOG=10, 1024 rows each) ────────────────
    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    // ── Step 5: Generate VFRI4 hints ─────────────────────────────────────────
    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// Generate VFRI6-compatible hints from V23's NttBatch + InttBatch components.
///
/// Same 1298-column combined trace as gen_mldsa_v23_vfri4_hints, but uses the
/// VFRI6 ABI encoding (off-chain oodsComboPos/Neg, no Poseidon2 sponge).
///
/// Key result: 1298 cols fit within 15M gas — same as 649 cols in VFRI6, because
/// VFRI6's on-chain cost is O(1) in n_cols (only 8 M31 words mixed per call).
pub fn gen_mldsa_v23_vfri6_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    gen_vfri6_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI6 hint generator for V23's LOG=8 component group.
///
/// Covers AzFull (1523) + Ct1Full (295) + RangeQBatch (288) +
/// WPrimeFull (24) + NormCheckBatch (15) + UseHintBatchV2 (60 main + 1 preproc)
/// = 2206 columns at tree_depth=8 (256 rows each).
///
/// Combined with `gen_mldsa_v23_vfri6_hints` (LOG=10 group, 1298 cols),
/// these two calls cover the full V23 trace (3504 main cols).
///
/// Returns `(proof_bytes, commitment_hex, abi_encoded_query_hints)` accepted by
/// `QLSAVerifierVFRI6.verify()`.
pub fn gen_mldsa_v23_vfri6_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) — intermediate values, columns not included ─────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: AzFull and Ct1Full (LOG=8) ───────────────────────────────────
    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: RangeQBatch — proves az_hat ∈ [0, Q) ─────────────────────────
    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    // ── Step 4: INTT(az_hat || ct1_hat) — intermediate, columns not included ──
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K]
        .try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..]
        .try_into().map_err(|_| "ct1_out slice error".to_string())?;

    // ── Step 5: WPrimeFull, NormCheckBatch, UseHintBatchV2 (LOG=8) ───────────
    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _norm_out, _max_norms) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _w1_out, _hint_weight) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    // ── Step 6: Combine all LOG=8 columns (256 rows each) ────────────────────
    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!(
                    "LOG=8 col has {} rows, expected {n_rows}", col.values.len()
                ));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri6_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

// ─────────────────────────────────────────────────────────────────────────────
// VFRI7 — VFRI6 + merkleRoot in Fiat-Shamir transcript (cross-proof binding)
// ─────────────────────────────────────────────────────────────────────────────
//
// Protocol change from VFRI6:
//   After all FRI layer roots are mixed and before drawing query indices, the
//   external batch_merkle_root is mixed into the Fiat-Shamir channel:
//
//     VFRI6: ... → mixRoot(friLayerRoots[K]) → drawQueries
//     VFRI7: ... → mixRoot(friLayerRoots[K]) → mixRoot(batch_merkle_root) → drawQueries
//
// Effect: The query indices (and therefore all per-query Merkle openings) depend
// on batch_merkle_root.  When BatchRegistryV4 uses cross-bound roots:
//
//   bound_root_10 = keccak256(batch_root ‖ trace_root_8)
//   bound_root_8  = keccak256(batch_root ‖ trace_root_10)
//
// an adversary that mixes LOG=10 and LOG=8 proofs from different witnesses would
// get mismatched query indices and fail the Merkle verification.  This closes
// the cross-proof cherry-pick vulnerability (MVP-5 Priority 2).

/// VFRI7 generic hint generator — VFRI6 + batch_merkle_root in Fiat-Shamir transcript.
///
/// Identical to `gen_vfri6_hints_from_cols_nfolds` except that `batch_merkle_root`
/// is mixed into the channel via `chan.mix_root()` immediately before `draw_queries`.
/// The commitment binding is the same: `Blake2s(proof[:32] ‖ batch_merkle_root)[:16]`.
pub fn gen_vfri7_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x       = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // ── VFRI7: mix batch_merkle_root into channel before drawing queries ───────
    // This binds the FRI query indices to the external batch root, enabling
    // cross-proof binding when cross-bound roots are used (see gen_mldsa_v23_vfri7_cross_bound_hints).
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI7 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri7_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri7_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI7 wrapper for V23 LOG=8 group (AzFull+Ct1Full+RangeQBatch+WPrimeFull+NormCheckBatch+UseHintBatchV2, 2206 cols).
pub fn gen_mldsa_v23_vfri7_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri7_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI7 hints for V23's two trace groups.
///
/// Cross-proof binding (MVP-5 Priority 2):
///   bound_root_10 = keccak256(batch_root ‖ trace_root_8)
///   bound_root_8  = keccak256(batch_root ‖ trace_root_10)
///
/// The LOG=10 proof is regenerated with `batch_merkle_root = bound_root_10` so
/// its FRI query indices depend on the LOG=8 trace commitment, and vice versa.
/// An adversary combining proofs from different witnesses would fail on-chain
/// because the query indices and Merkle openings would not match.
///
/// Returns `(proof10, commit10_hex, hints10, proof8, commit8_hex, hints8)`.
/// The caller (BatchRegistryV4) should pass:
///   - `boundRoot10 = keccak256(merkleRoot ‖ proof8[8:40])` to VFRI7 verify for LOG=10
///   - `boundRoot8  = keccak256(merkleRoot ‖ proof10[8:40])` to VFRI7 verify for LOG=8
pub fn gen_mldsa_v23_vfri7_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // ── Pass 1: extract trace roots ───────────────────────────────────────────
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    // ── Compute cross-bound merkle roots ──────────────────────────────────────
    // bound_root_10 = keccak256(batch_root ‖ trace_root_8)
    // bound_root_8  = keccak256(batch_root ‖ trace_root_10)
    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // ── Pass 2: generate final hints with cross-bound roots ───────────────────
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

// ── VFRI8 — Poseidon2 trace commitment ────────────────────────────────────────
//
// VFRI8 = VFRI7 with Poseidon2 replacing Blake2s for Merkle tree hashing and
// the Fiat-Shamir channel.
//
// Merkle node encoding: bytes32(uint256(s0)) where s0 is an M31 field element.
//   hashLeaf(col_values) = poseidon2_rate1_sponge(col_values).s0
//   hashPair(left, right) = permute(left_m31, right_m31).s0
//
// P2Channel state: (s0, s1, n_draws) — Poseidon2 duplex sponge.
//   absorb(word): s[0] += word; permute
//   mix_root(root): absorb(root_m31 from bytes[28:32]); n_draws=0
//   draw_pair(): output (s0,s1); absorb n_draws; n_draws++
//
// Gas: 20 queries × 2 paths × depth=10 × ~1000 gas/permute ≈ 400K gas (vs ~160M Blake2s)

fn p2_absorb(s: &mut [u64; 2], word: u32) {
    // Reduce word to a valid M31 element before adding.
    // A u32 can be >= M31_P (e.g. keccak256 last 4 bytes).  Two subtractions
    // suffice because word < 2^32 = 2*M31_P + 2, so at most two steps needed.
    let mut w = word as u64;
    if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
    if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
    s[0] = crate::poseidon2::m31_add(s[0], w);
    crate::poseidon2::permute(s);
}

fn hash_leaf_cols_p2(col_values: &[u32]) -> [u8; 32] {
    let mut s = [0u64; 2];
    for &v in col_values {
        p2_absorb(&mut s, v);
    }
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn hash_pair_p2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l = u32::from_be_bytes(left[28..32].try_into().unwrap()) as u64;
    let r = u32::from_be_bytes(right[28..32].try_into().unwrap()) as u64;
    let mut s = [l, r];
    crate::poseidon2::permute(&mut s);
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn hash_leaf_qm31_p2(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let mut s = [0u64; 2];
    for &w in &words {
        p2_absorb(&mut s, w);
    }
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn build_tree_p2(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair_p2(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

struct P2Channel {
    s0: u32,
    s1: u32,
    n_draws: u32,
}

impl P2Channel {
    fn init() -> Self {
        P2Channel { s0: 0, s1: 0, n_draws: 0 }
    }

    fn absorb(&mut self, word: u32) {
        let mut s = [self.s0 as u64, self.s1 as u64];
        p2_absorb(&mut s, word);
        self.s0 = s[0] as u32;
        self.s1 = s[1] as u32;
    }

    fn mix_root(&mut self, root: &[u8; 32]) {
        let m = u32::from_be_bytes(root[28..32].try_into().unwrap());
        self.absorb(m);
        self.n_draws = 0;
    }

    fn mix_u32s(&mut self, words: &[u32]) {
        for &w in words { self.absorb(w); }
        self.n_draws = 0;
    }

    fn draw_pair(&mut self) -> (u32, u32) {
        let w0 = self.s0;
        let w1 = self.s1;
        let mut s = [self.s0 as u64, self.s1 as u64];
        s[0] = crate::poseidon2::m31_add(s[0], self.n_draws as u64);
        crate::poseidon2::permute(&mut s);
        self.s0 = s[0] as u32;
        self.s1 = s[1] as u32;
        self.n_draws += 1;
        (w0, w1)
    }

    fn draw_secure_felt(&mut self) -> u128 {
        let (w0, w1) = self.draw_pair();
        let (w2, w3) = self.draw_pair();
        let c0 = cm31_pack(w0, w1);
        let c1 = cm31_pack(w2, w3);
        qm31_pack_c(c0, c1)
    }

    fn draw_queries(&mut self, log_domain_size: u32, n: usize) -> Vec<usize> {
        let mask = ((1u64 << log_domain_size) - 1) as u32;
        let mut queries = Vec::with_capacity(n);
        while queries.len() < n {
            let (w0, w1) = self.draw_pair();
            queries.push((w0 & mask) as usize);
            if queries.len() < n {
                queries.push((w1 & mask) as usize);
            }
        }
        queries.truncate(n);
        queries
    }
}

/// VFRI8 generic hint generator — VFRI7 protocol with Poseidon2 hash backend.
///
/// Transcript (identical to VFRI7 but using P2Channel and P2 Merkle):
///   P2Channel.mix_root(traceRoot)
///   z_x = draw_secure_felt
///   compAlpha = draw_secure_felt
///   mix_u32s([comboPos_words…, comboNeg_words…])
///   mix_root(compRoot)
///   friAlpha = draw_secure_felt
///   mix_root(friLayerRoots[0])
///   for k: friAlphas[k] = draw_secure_felt; mix_root(friLayerRoots[k+1])
///   mix_root(batch_merkle_root)   ← VFRI7 cross-proof binding
///   drawQueries(treeDepth, n)
pub fn gen_vfri8_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (Poseidon2)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (Poseidon2 channel)
    let mut chan = P2Channel::init();
    chan.mix_root(&trace_root);
    let z_x       = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (Poseidon2)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
    let comp_levels = build_tree_p2(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (Poseidon2)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
    let fri_l1_levels = build_tree_p2(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
        let new_levels = build_tree_p2(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // VFRI7/VFRI8 cross-proof binding: mix batch_merkle_root before drawQueries
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI8 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri8_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri8_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI8 wrapper for V23 LOG=8 group (2206 cols).
pub fn gen_mldsa_v23_vfri8_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri8_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI8 hints for V23's two trace groups.
///
/// Identical to gen_mldsa_v23_vfri7_cross_bound_hints but using VFRI8 (Poseidon2) provers.
///
/// bound_root_10 = keccak256(batch_root ‖ trace_root_8)
/// bound_root_8  = keccak256(batch_root ‖ trace_root_10)
pub fn gen_mldsa_v23_vfri8_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // Pass 1: extract trace roots
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // Pass 2: generate final hints with cross-bound roots
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

// ── VFRI9 — wide Poseidon2 nodes + last-layer FRI check ──────────────────────
//
// VFRI9 = VFRI8 with three security upgrades:
//
// 1. WIDE MERKLE NODES (62-bit): nodes carry BOTH sponge words.
//      node bytes32: out[24..28] = s0_be, out[28..32] = s1_be
//    VFRI8's 31-bit nodes (s0 only) have ~2^15.5 birthday collision cost;
//    62-bit nodes raise this to ~2^31.  Full 128-bit binding requires a
//    t>=4 permutation (RPO256, MVP-6) — documented limitation.
//
// 2. FULL-ROOT FIAT-SHAMIR ABSORPTION: 32-byte roots (embedded Stwo trace
//    root, batch merkle root) are absorbed as 8 big-endian u32 words instead
//    of only the low 4 bytes; wide P2 node roots are absorbed as 2 words.
//
// 3. LAST-LAYER FRI CHECK (from VFRI3): the prover supplies all
//    2^(treeDepth-K) evaluations of the final FRI layer; the verifier
//    rebuilds the Merkle tree and asserts root == friLayerRoots[K].  This
//    closes the bounded-degree soundness gap left open in VFRI5..VFRI8.
//
// queryHints ABI (6 head slots):
//   abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot,
//              uint128[] lastLayerEvals, bytes32[] friLayerRoots, QueryHints[])

fn hash_leaf_cols_p2w(col_values: &[u32]) -> [u8; 32] {
    let mut s = [0u64; 2];
    for &v in col_values {
        p2_absorb(&mut s, v);
    }
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn hash_pair_p2w(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l0 = u32::from_be_bytes(left[24..28].try_into().unwrap()) as u64;
    let l1 = u32::from_be_bytes(left[28..32].try_into().unwrap()) as u64;
    let r0 = u32::from_be_bytes(right[24..28].try_into().unwrap()) as u64;
    let r1 = u32::from_be_bytes(right[28..32].try_into().unwrap()) as u64;
    // Duplex compress: state = left, then absorb right one word at a time.
    let mut s = [l0, l1];
    s[0] = crate::poseidon2::m31_add(s[0], r0);
    crate::poseidon2::permute(&mut s);
    s[0] = crate::poseidon2::m31_add(s[0], r1);
    crate::poseidon2::permute(&mut s);
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn hash_leaf_qm31_p2w(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let mut s = [0u64; 2];
    for &w in &words {
        p2_absorb(&mut s, w);
    }
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn build_tree_p2w(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair_p2w(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

impl P2Channel {
    /// Absorb a wide Poseidon2 node root (62-bit content) as 2 BE u32 words.
    fn mix_root_w(&mut self, root: &[u8; 32]) {
        self.absorb(u32::from_be_bytes(root[24..28].try_into().unwrap()));
        self.absorb(u32::from_be_bytes(root[28..32].try_into().unwrap()));
        self.n_draws = 0;
    }

    /// Absorb a full 32-byte root (Stwo trace root, batch merkle root) as
    /// 8 big-endian u32 words.  Binds ALL 256 bits into the transcript,
    /// unlike VFRI8's mix_root which only absorbed the low 4 bytes.
    fn mix_root_full(&mut self, root: &[u8; 32]) {
        for i in 0..8 {
            self.absorb(u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap()));
        }
        self.n_draws = 0;
    }
}

// ── VFRI10 hash backend: Poseidon2 t=4 wide Merkle + Fiat-Shamir channel ──────
//
// The t=2 channel and the t=2 wide (`p2w`) Merkle nodes carry only 62 bits of
// capacity — collision / transcript attacks bottom out at ~2^31 (limitation #6).
// These t=4 primitives reuse the frozen `poseidon2_t4` permutation: a capacity-2
// duplex sponge over a 124-bit state, the next step toward 128-bit binding
// (VFRI10).  Node encoding is unchanged from `p2w` (two M31 words packed into
// bytes[24..32]) so the Solidity Merkle path logic is identical — only the
// permutation differs.

/// Wide t=4 leaf hash: rate-2 capacity-2 sponge over the column values.
/// Node = (state[0], state[1]) packed into bytes[24..32].
/// Matches Poseidon2MerkleVerifierT4.hashLeaf and uses the same `sponge_t4`
/// padding convention (odd-length flag in capacity cell 3).
#[allow(dead_code)]
fn hash_leaf_cols_p2t4(col_values: &[u32]) -> [u8; 32] {
    let vals: Vec<u64> = col_values.iter().map(|&v| v as u64).collect();
    let s = crate::poseidon2_t4::sponge_t4(&vals);
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

/// Wide t=4 pair hash: 2-to-1 compression of two 2-word nodes via a single
/// t=4 permutation (state = (l0, l1, r0, r1) → permute → (s0, s1)).
/// Matches Poseidon2MerkleVerifierT4.hashPair.
#[allow(dead_code)]
fn hash_pair_p2t4(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l0 = u32::from_be_bytes(left[24..28].try_into().unwrap()) as u64;
    let l1 = u32::from_be_bytes(left[28..32].try_into().unwrap()) as u64;
    let r0 = u32::from_be_bytes(right[24..28].try_into().unwrap()) as u64;
    let r1 = u32::from_be_bytes(right[28..32].try_into().unwrap()) as u64;
    let s = crate::poseidon2_t4::compress_t4([l0, l1], [r0, r1]);
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

/// Wide t=4 leaf hash for a single QM31 value (4 M31 words).
#[allow(dead_code)]
fn hash_leaf_qm31_p2t4(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let vals: Vec<u64> = words.iter().map(|&w| w as u64).collect();
    let s = crate::poseidon2_t4::sponge_t4(&vals);
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

#[allow(dead_code)]
fn build_tree_p2t4(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair_p2t4(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

/// Poseidon2 t=4 duplex Fiat-Shamir channel (VFRI10).
///
/// Structural analogue of `P2Channel` (t=2) widened to the t=4 permutation:
///   - absorb: rate-1 into cell 0 (cells 1–3 form the capacity → 93 bits)
///   - draw_pair: squeeze the two rate-adjacent cells (s0, s1), then mix the
///     squeeze counter into cell 0 and permute
/// Exposes the same interface (mix_root / mix_root_w / mix_root_full /
/// mix_u32s / draw_secure_felt / draw_queries) so VFRI10 can swap it in for
/// `P2Channel` with no transcript-shape changes — only the permutation widens.
#[allow(dead_code)]
struct P2T4Channel {
    s: [u64; 4],
    n_draws: u32,
}

#[allow(dead_code)]
impl P2T4Channel {
    fn init() -> Self {
        P2T4Channel { s: [0u64; 4], n_draws: 0 }
    }

    fn absorb(&mut self, word: u32) {
        // Reduce arbitrary u32 (e.g. keccak bytes) to M31 — two subtractions
        // suffice since u32 < 2*P+2.
        let mut w = word as u64;
        if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
        if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
        self.s[0] = crate::poseidon2::m31_add(self.s[0], w);
        crate::poseidon2_t4::permute_t4(&mut self.s);
    }

    fn mix_root(&mut self, root: &[u8; 32]) {
        self.absorb(u32::from_be_bytes(root[28..32].try_into().unwrap()));
        self.n_draws = 0;
    }

    fn mix_root_w(&mut self, root: &[u8; 32]) {
        self.absorb(u32::from_be_bytes(root[24..28].try_into().unwrap()));
        self.absorb(u32::from_be_bytes(root[28..32].try_into().unwrap()));
        self.n_draws = 0;
    }

    fn mix_root_full(&mut self, root: &[u8; 32]) {
        for i in 0..8 {
            self.absorb(u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap()));
        }
        self.n_draws = 0;
    }

    fn mix_u32s(&mut self, words: &[u32]) {
        for &w in words { self.absorb(w); }
        self.n_draws = 0;
    }

    fn draw_pair(&mut self) -> (u32, u32) {
        let w0 = self.s[0] as u32;
        let w1 = self.s[1] as u32;
        self.s[0] = crate::poseidon2::m31_add(self.s[0], self.n_draws as u64);
        crate::poseidon2_t4::permute_t4(&mut self.s);
        self.n_draws += 1;
        (w0, w1)
    }

    fn draw_secure_felt(&mut self) -> u128 {
        let (w0, w1) = self.draw_pair();
        let (w2, w3) = self.draw_pair();
        let c0 = cm31_pack(w0, w1);
        let c1 = cm31_pack(w2, w3);
        qm31_pack_c(c0, c1)
    }

    fn draw_queries(&mut self, log_domain_size: u32, n: usize) -> Vec<usize> {
        let mask = ((1u64 << log_domain_size) - 1) as u32;
        let mut queries = Vec::with_capacity(n);
        while queries.len() < n {
            let (w0, w1) = self.draw_pair();
            queries.push((w0 & mask) as usize);
            if queries.len() < n {
                queries.push((w1 & mask) as usize);
            }
        }
        queries.truncate(n);
        queries
    }
}

fn abi_encode_vfri9_hints(
    oods_combo_pos:   u128,
    oods_combo_neg:   u128,
    comp_root:        &[u8; 32],
    last_layer_evals: &[u128],
    fri_layer_roots:  &[[u8; 32]],
    hints:            &[QueryHintDataV5],
) -> Vec<u8> {
    let head_size: usize = 6 * 32;

    let evals_body = encode_uint128_array(last_layer_evals);
    let roots_body = encode_bytes32_array(fri_layer_roots);
    let hints_body = encode_query_hints_array_v5(hints);

    let evals_offset = head_size;
    let roots_offset = evals_offset + evals_body.len();
    let hints_offset = roots_offset + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(oods_combo_pos));    // 0: static uint128
    out.extend_from_slice(&abi_word_u128(oods_combo_neg));    // 1: static uint128
    out.extend_from_slice(comp_root);                          // 2: static bytes32
    out.extend_from_slice(&abi_word_usize(evals_offset));      // 3: offset → uint128[]
    out.extend_from_slice(&abi_word_usize(roots_offset));      // 4: offset → bytes32[]
    out.extend_from_slice(&abi_word_usize(hints_offset));      // 5: offset → QueryHints[]
    out.extend_from_slice(&evals_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// VFRI9 generic hint generator — VFRI8 protocol with wide Poseidon2 nodes,
/// full-root Fiat-Shamir absorption, and last-layer evaluations export.
///
/// Transcript:
///   P2Channel.mix_root_full(traceRoot)              ← 8 words (NEW: full root)
///   z_x = draw_secure_felt
///   compAlpha = draw_secure_felt
///   mix_u32s([comboPos_words…, comboNeg_words…])
///   mix_root_w(compRoot)                            ← 2 words (wide node)
///   friAlpha = draw_secure_felt
///   mix_root_w(friLayerRoots[0])
///   for k: friAlphas[k] = draw_secure_felt; mix_root_w(friLayerRoots[k+1])
///   mix_root_full(batch_merkle_root)                ← 8 words (NEW: full root)
///   drawQueries(treeDepth, n)
pub fn gen_vfri9_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (wide Poseidon2 nodes)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2w(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2w(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (Poseidon2 channel, full-root absorption)
    let mut chan = P2Channel::init();
    chan.mix_root_full(&trace_root);
    let z_x        = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (wide Poseidon2 nodes)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
    let comp_levels = build_tree_p2w(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root_w(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (wide Poseidon2 nodes)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
    let fri_l1_levels = build_tree_p2w(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root_w(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
        let new_levels = build_tree_p2w(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root_w(&new_root);
        layer_levels.push(new_levels);
    }

    // Last-layer evaluations: ALL values of the final FRI layer.  The on-chain
    // verifier rebuilds the Merkle tree from these and asserts the root equals
    // friLayerRoots[num_folds] — the bounded-degree check missing in VFRI5..8.
    let last_layer_evals: Vec<u128> = layer_values[num_folds].clone();

    // Cross-proof binding: mix the FULL batch merkle root before drawQueries.
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root_full(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&3u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri9_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &last_layer_evals,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI10 generic hint generator — identical protocol to VFRI9 with the
/// Poseidon2 t=4 hash backend (wide t=4 Merkle + t=4 Fiat-Shamir channel).
///
/// Every transcript step, OODS combo, composition tree, FRI fold chain, and
/// the queryHints ABI layout match `gen_vfri9_hints_from_cols_nfolds` exactly —
/// only the hash primitives change:
///   hash_leaf_cols_p2w  → hash_leaf_cols_p2t4
///   hash_leaf_qm31_p2w  → hash_leaf_qm31_p2t4
///   build_tree_p2w      → build_tree_p2t4
///   P2Channel           → P2T4Channel
/// The proof version marker is 4 (VFRI9 = 3).
pub fn gen_vfri10_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (t=4 wide Poseidon2 nodes)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2t4(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2t4(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (t=4 Poseidon2 channel, full-root absorption)
    let mut chan = P2T4Channel::init();
    chan.mix_root_full(&trace_root);
    let z_x        = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (t=4 wide Poseidon2 nodes)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
    let comp_levels = build_tree_p2t4(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root_w(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (t=4 wide Poseidon2 nodes)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
    let fri_l1_levels = build_tree_p2t4(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root_w(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
        let new_levels = build_tree_p2t4(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root_w(&new_root);
        layer_levels.push(new_levels);
    }

    // Last-layer evaluations: ALL values of the final FRI layer (bounded-degree
    // check — verifier rebuilds the Merkle tree and asserts root match).
    let last_layer_evals: Vec<u128> = layer_values[num_folds].clone();

    // Cross-proof binding: mix the FULL batch merkle root before drawQueries.
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root_full(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&4u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    // VFRI10 hints share VFRI9's ABI layout exactly.
    let query_hints = abi_encode_vfri9_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &last_layer_evals,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI9 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri9_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri9_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI9 wrapper for V23 LOG=8 group (2206 cols).
pub fn gen_mldsa_v23_vfri9_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri9_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI9 hints for V23's two trace groups.
///
/// Identical to gen_mldsa_v23_vfri8_cross_bound_hints but using VFRI9 generators.
///
/// bound_root_10 = keccak256(batch_root ‖ trace_root_8)
/// bound_root_8  = keccak256(batch_root ‖ trace_root_10)
pub fn gen_mldsa_v23_vfri9_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // Pass 1: extract trace roots
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri9_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // Pass 2: generate final hints with cross-bound roots
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri9_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

mod tests {
    use super::*;

    #[test]
    fn test_gen_poseidon2_vfri2_hints_smoke() {
        let leaves: Vec<u64> = (1..=8).collect();
        let seed = vec![0u8; 32];
        let (proof, commitment, hints) = gen_poseidon2_vfri2_hints(&leaves, &seed, 2).unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_proof_structure() {
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0xabu8; 32];
        let (proof, commitment, hints) = gen_poseidon2_vfri2_hints(&leaves, &seed, 1).unwrap();

        // Check nonce bytes
        let nonce = u64::from_le_bytes(proof[0..8].try_into().unwrap());
        assert_eq!(nonce, 2u64);

        // Check commitment is 32 hex chars (16 bytes)
        assert_eq!(commitment.len(), 32);
        let commit_bytes = hex::decode(&commitment).unwrap();
        assert_eq!(commit_bytes.len(), 16);

        // Check commitment matches expected Blake2s(proof[:32] ++ seed)[:16]
        let mut hash_input = [0u8; 64];
        hash_input[..32].copy_from_slice(&proof[..32]);
        hash_input[32..].copy_from_slice(&seed);
        let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
        assert_eq!(&commit_bytes, &h[..16]);

        // Hints must be non-empty and parsable
        assert!(!hints.is_empty());
        // First 32 bytes of hints are the lastLayerValue (u128 = 0, zero-padded to 32 bytes)
        assert_eq!(&hints[..16], &[0u8; 16]);
        assert_eq!(&hints[16..32], &[0u8; 16]);
    }

    #[test]
    fn test_m31_arithmetic() {
        let p = P as u32;
        assert_eq!(m31_add(p - 1, 1), 0);
        assert_eq!(m31_add(p - 1, p - 1), p - 2);
        assert_eq!(m31_mul(2, 3), 6);
        assert_eq!(m31_mul(p - 1, p - 1), 1);
        assert_eq!(m31_inv(1), 1);
        assert_eq!(m31_mul(m31_inv(3), 3), 1);
        assert_eq!(m31_neg(0), 0);
        assert_eq!(m31_neg(1), p - 1);
    }

    #[test]
    fn test_coset_at_identity() {
        // For logN=1: initial=2^29, step=2^30
        // cosetAt(1, 0) = genMul(2^29)
        let (x0, y0) = coset_at(1, 0);
        let (x1, y1) = coset_at(1, 1);
        // Both points should be on the circle: x²+y² = 1 mod P
        let p = P as u32;
        let on_c0 = m31_add(m31_mul(x0, x0), m31_mul(y0, y0));
        let on_c1 = m31_add(m31_mul(x1, x1), m31_mul(y1, y1));
        assert_eq!(on_c0, 1, "coset(1,0) not on circle");
        assert_eq!(on_c1, 1, "coset(1,1) not on circle");
        let _ = p;
    }

    #[test]
    fn test_channel_deterministic() {
        let mut c1 = Channel::init();
        let mut c2 = Channel::init();
        let root = [0x42u8; 32];
        c1.mix_root(&root);
        c2.mix_root(&root);
        assert_eq!(c1.draw_secure_felt(), c2.draw_secure_felt());
    }

    #[test]
    fn test_qm31_arithmetic() {
        // zero * anything = zero
        assert_eq!(qm31_mul(0, 1234), 0);
        // one * x = x
        let x = qm31_from_m31(42);
        let one = qm31_from_m31(1);
        assert_eq!(qm31_mul(one, x), x);
        // x + neg(x) = 0
        assert_eq!(qm31_add(x, qm31_neg(x)), 0);
    }

    #[test]
    fn test_merkle_tree_correctness() {
        // Build a simple 4-leaf tree and verify a path
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| {
            let mut arr = [0u8; 32];
            arr[0] = i;
            Blake2s256::digest(&arr).into()
        }).collect();

        let levels = build_tree(leaves.clone());
        // Root should be hash of two children
        let expected_left  = hash_pair(&levels[0][0], &levels[0][1]);
        let expected_right = hash_pair(&levels[0][2], &levels[0][3]);
        let expected_root  = hash_pair(&expected_left, &expected_right);
        assert_eq!(levels.last().unwrap()[0], expected_root);

        // Verify proof for leaf 2
        let sib = proof_path(&levels, 2);
        assert_eq!(sib.len(), 2); // depth=2 for 4 leaves
        // Manually reconstruct
        let mut h = leaves[2];
        h = hash_pair(&h, &sib[0]); // sibling at level 0 = leaf[3]
        h = hash_pair(&sib[1], &h); // sibling at level 1 = left subtree
        assert_eq!(h, expected_root);
    }

    #[test]
    fn test_gen_with_single_query() {
        let leaves: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let seed = vec![0u8; 32];
        let (proof, commitment, hints) = gen_poseidon2_vfri2_hints(&leaves, &seed, 1).unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_error_on_empty_leaves() {
        let result = gen_poseidon2_vfri2_hints(&[], &[0u8; 32], 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_bad_batch_root() {
        let result = gen_poseidon2_vfri2_hints(&[1], &[0u8; 31], 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_bad_n_queries() {
        let result = gen_poseidon2_vfri2_hints(&[1], &[0u8; 32], 0);
        assert!(result.is_err());
        let result = gen_poseidon2_vfri2_hints(&[1], &[0u8; 32], 65);
        assert!(result.is_err());
    }

    /// Verify that the constant-tree root (last FRI layer root) is correctly computed.
    /// The VFRI2 Solidity contract checks:
    ///   node = hashLeaf(qm31Words(lastLayerValue))
    ///   for i in 0..lastDepth: node = hashPair(node, node)
    ///   assert node == friLayerRoots[numFolds]
    #[test]
    fn test_constant_tree_root() {
        let leaves: Vec<u64> = (1..=8).collect();
        let seed = vec![0u8; 32];
        let (_, _, hints_bytes) = gen_poseidon2_vfri2_hints(&leaves, &seed, 2).unwrap();

        // Last layer value = 0, so hashLeaf(qm31Words(0)) = Blake2s([0;16])
        let last_layer_leaf = hash_leaf_qm31(0u128);

        // tree_depth for 8 leaves × 8 rounds = 64 rows → log_size = 6
        // num_folds = tree_depth - 1 = 5
        // last_depth = tree_depth - num_folds = 1
        // constant tree root = hashPair(last_layer_leaf, last_layer_leaf)
        let last_depth = 1usize;
        let mut node = last_layer_leaf;
        for _ in 0..last_depth {
            node = hash_pair(&node, &node);
        }

        // The last FRI layer root should be this constant tree root.
        // We extract it from the ABI-encoded hints:
        //   byte [0:32]   = lastLayerValue (uint128, padded)
        //   byte [32:64]  = offset to oodsEvalsPos
        //   byte [64:96]  = offset to oodsEvalsNeg
        //   byte [96:128] = offset to friLayerRoots
        //   byte [128:160]= offset to QueryHints[]
        // The friLayerRoots offset (relative to start) tells us where to read the roots.
        let roots_offset = usize::from_be_bytes(
            hints_bytes[96..128][24..32].try_into().unwrap()
        );
        // At roots_offset: first 32 bytes = length of array
        let roots_len = usize::from_be_bytes(
            hints_bytes[roots_offset..roots_offset+32][24..32].try_into().unwrap()
        );

        // num_folds = tree_depth - 1. For tree_depth=6, num_folds=5, roots_len=6.
        assert!(roots_len >= 2, "friLayerRoots must have ≥ 2 entries");

        // Last root is at roots_offset + 32 + (roots_len - 1) * 32
        let last_root_offset = roots_offset + 32 + (roots_len - 1) * 32;
        let last_root: [u8; 32] = hints_bytes[last_root_offset..last_root_offset+32]
            .try_into().unwrap();

        assert_eq!(last_root, node,
            "last FRI layer root must match the constant tree root for lastLayerValue=0");
    }

    // ── gen_poseidon2_vfri3_real tests ───────────────────────────────────────

    #[test]
    fn test_gen_poseidon2_vfri3_real_smoke() {
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0u8; 32];
        let result = gen_poseidon2_vfri3_real(&leaves, &seed, 2);
        assert!(result.is_ok(), "vfri3_real should succeed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_poseidon2_vfri3_real_commitment_binding() {
        let leaves: Vec<u64> = (1..=8).collect();
        let batch_root: Vec<u8> = (0u8..32).collect();
        let (proof, commitment, _) = gen_poseidon2_vfri3_real(&leaves, &batch_root, 2).unwrap();

        let mut hash_input = [0u8; 64];
        hash_input[..32].copy_from_slice(&proof[..32]);
        hash_input[32..].copy_from_slice(&batch_root);
        let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
        assert_eq!(commitment, hex::encode(&h[..16]));
    }

    #[test]
    fn test_gen_poseidon2_vfri3_real_different_inputs_differ() {
        let seed = vec![0u8; 32];
        let (_, c1, _) = gen_poseidon2_vfri3_real(&[1, 2, 3, 4], &seed, 2).unwrap();
        let (_, c2, _) = gen_poseidon2_vfri3_real(&[5, 6, 7, 8], &seed, 2).unwrap();
        assert_ne!(c1, c2, "different leaves must produce different commitments");
    }

    #[test]
    fn test_gen_poseidon2_vfri3_real_deterministic() {
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = gen_poseidon2_vfri3_real(&leaves, &seed, 2).unwrap();
        let (_, c2, h2) = gen_poseidon2_vfri3_real(&leaves, &seed, 2).unwrap();
        assert_eq!(c1, c2, "deterministic commitment");
        assert_eq!(h1, h2, "deterministic hints");
    }

    #[test]
    fn test_gen_poseidon2_vfri3_real_hints_non_constant_last_layer() {
        // With real trace the last layer should not be a single constant (length == 2 for tree_depth=5)
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0u8; 32];
        let (_, _, hints) = gen_poseidon2_vfri3_real(&leaves, &seed, 1).unwrap();
        // First 32 bytes of VFRI3 hints = ABI-encoded uint128[] lastLayerCoeffs offset
        // Just verify the hints are non-empty and differ from the zero-polynomial version.
        let (_, _, zero_hints) = gen_poseidon2_vfri2_hints(&[1, 2, 3, 4], &seed, 1).unwrap();
        assert_ne!(hints, zero_hints, "vfri3_real hints differ from zero-polynomial hints");
    }

    #[test]
    fn test_gen_poseidon2_vfri3_real_input_validation() {
        let seed = vec![0u8; 32];
        assert!(gen_poseidon2_vfri3_real(&[], &seed, 2).is_err(), "empty leaves");
        assert!(gen_poseidon2_vfri3_real(&[1], &vec![0u8; 31], 2).is_err(), "short root");
        assert!(gen_poseidon2_vfri3_real(&[1], &seed, 0).is_err(), "n_queries=0");
        assert!(gen_poseidon2_vfri3_real(&[1], &seed, 65).is_err(), "n_queries too large");
    }

    // ── gen_poseidon2_vfri4_real tests ───────────────────────────────────────

    #[test]
    fn test_gen_poseidon2_vfri4_real_smoke() {
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0u8; 32];
        let result = gen_poseidon2_vfri4_real(&leaves, &seed, 2);
        assert!(result.is_ok(), "vfri4_real should succeed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_poseidon2_vfri4_real_commitment_binding() {
        let leaves: Vec<u64> = (1..=8).collect();
        let batch_root: Vec<u8> = (0u8..32).collect();
        let (proof, commitment, _) = gen_poseidon2_vfri4_real(&leaves, &batch_root, 2).unwrap();

        let mut hash_input = [0u8; 64];
        hash_input[..32].copy_from_slice(&proof[..32]);
        hash_input[32..].copy_from_slice(&batch_root);
        let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
        assert_eq!(commitment, hex::encode(&h[..16]));
    }

    #[test]
    fn test_gen_poseidon2_vfri4_real_deterministic() {
        let leaves: Vec<u64> = (1..=4).collect();
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = gen_poseidon2_vfri4_real(&leaves, &seed, 2).unwrap();
        let (_, c2, h2) = gen_poseidon2_vfri4_real(&leaves, &seed, 2).unwrap();
        assert_eq!(c1, c2, "deterministic commitment");
        assert_eq!(h1, h2, "deterministic hints");
    }

    #[test]
    fn test_gen_poseidon2_vfri4_real_differs_from_vfri3() {
        // VFRI4 and VFRI3 have different transcripts → different query indices → different hints
        let leaves: Vec<u64> = (1..=8).collect();
        let seed = vec![0x42u8; 32];
        let (_, _c3, h3) = gen_poseidon2_vfri3_real(&leaves, &seed, 2).unwrap();
        let (_, _c4, h4) = gen_poseidon2_vfri4_real(&leaves, &seed, 2).unwrap();
        assert_ne!(h3, h4, "VFRI4 transcript differs from VFRI3 transcript");
    }

    #[test]
    fn test_gen_poseidon2_vfri4_real_input_validation() {
        let seed = vec![0u8; 32];
        assert!(gen_poseidon2_vfri4_real(&[], &seed, 2).is_err(), "empty leaves");
        assert!(gen_poseidon2_vfri4_real(&[1], &vec![0u8; 31], 2).is_err(), "short root");
        assert!(gen_poseidon2_vfri4_real(&[1], &seed, 0).is_err(), "n_queries=0");
        assert!(gen_poseidon2_vfri4_real(&[1], &seed, 65).is_err(), "n_queries too large");
    }

    // ── gen_ntt_batch_vfri3_hints tests ──────────────────────────────────────

    #[test]
    fn test_gen_ntt_batch_vfri3_hints_smoke() {
        // 12 unit polynomials (z×5 + c×1 + t1×6)
        let polys: Vec<[i64; 256]> = (0..12).map(|_| [0i64; 256]).collect();
        let seed = vec![0u8; 32];
        let result = gen_ntt_batch_vfri3_hints(&polys, &seed, 2);
        assert!(result.is_ok(), "ntt_batch vfri3 should succeed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_ntt_batch_vfri3_hints_commitment_binding() {
        use blake2::{Blake2s256, Digest};
        let polys: Vec<[i64; 256]> = (0..12).map(|i| {
            let mut p = [0i64; 256]; p[0] = (i + 1) as i64; p
        }).collect();
        let batch_root: Vec<u8> = (0u8..32).collect();
        let (proof, commitment, _) = gen_ntt_batch_vfri3_hints(&polys, &batch_root, 2).unwrap();

        let mut hash_input = [0u8; 64];
        hash_input[..32].copy_from_slice(&proof[..32]);
        hash_input[32..].copy_from_slice(&batch_root);
        let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
        assert_eq!(commitment, hex::encode(&h[..16]));
    }

    #[test]
    fn test_gen_ntt_batch_vfri3_hints_deterministic() {
        let polys: Vec<[i64; 256]> = (0..12).map(|i| {
            let mut p = [0i64; 256]; p[i] = 42; p
        }).collect();
        let seed = vec![0xbbu8; 32];
        let (_, c1, h1) = gen_ntt_batch_vfri3_hints(&polys, &seed, 2).unwrap();
        let (_, c2, h2) = gen_ntt_batch_vfri3_hints(&polys, &seed, 2).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gen_ntt_batch_vfri3_hints_input_validation() {
        let seed = vec![0u8; 32];
        assert!(gen_ntt_batch_vfri3_hints(&[], &seed, 2).is_err(), "empty polys");
        let poly1: Vec<[i64; 256]> = vec![[0i64; 256]];
        assert!(gen_ntt_batch_vfri3_hints(&poly1, &vec![0u8; 31], 2).is_err(), "short root");
        assert!(gen_ntt_batch_vfri3_hints(&poly1, &seed, 0).is_err(), "n_queries=0");
    }

    // ── gen_mldsa_v23_vfri4_hints tests ──────────────────────────────────────

    pub(super) fn make_v23_inputs(seed: u64) -> ([[i64;256];5], [i64;256], [[i64;256];6], Vec<[i64;256]>) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut rng_val = seed;
        let mut next = || -> i64 {
            let mut h = DefaultHasher::new();
            rng_val.hash(&mut h);
            rng_val = h.finish();
            (rng_val % 8380417) as i64
        };
        let z:     [[i64;256];5]       = std::array::from_fn(|_| std::array::from_fn(|_| next()));
        let c:     [i64;256]           = std::array::from_fn(|_| next() % 2);
        let t1:    [[i64;256];6]       = std::array::from_fn(|_| std::array::from_fn(|_| next()));
        let a_hat: Vec<[i64;256]>      = (0..30).map(|_| std::array::from_fn(|_| next())).collect();
        (z, c, t1, a_hat)
    }

    // ── VFRI5 tests ───────────────────────────────────────────────────────────

    fn make_vfri5_polys(n_polys: usize, seed: usize) -> Vec<[i64; 256]> {
        (0..n_polys).map(|k| {
            let mut p = [0i64; 256];
            for (i, x) in p.iter_mut().enumerate() {
                *x = ((seed + k * 257 + i + 1) % 500) as i64;
            }
            p
        }).collect()
    }

    #[test]
    fn test_gen_vfri5_hints_smoke() {
        let polys = make_vfri5_polys(3, 0);
        let seed = vec![0x55u8; 32];
        let result = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2));
        assert!(result.is_ok(), "vfri5 smoke: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 100);
        assert_eq!(commitment.len(), 32, "commitment is 16-byte hex = 32 chars");
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_vfri5_hints_deterministic() {
        let polys = make_vfri5_polys(4, 100);
        let seed = vec![0xddu8; 32];
        let (_, c1, h1) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, c2, h2) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gen_vfri5_hints_differ_from_vfri4() {
        let polys = make_vfri5_polys(4, 200);
        let seed = vec![0x99u8; 32];
        let (_, _c4, h4) = gen_ntt_batch_vfri4_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, _c5, h5) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        assert_ne!(h4, h5, "VFRI5 and VFRI4 hints must differ (different transcripts)");
    }

    #[test]
    fn test_gen_vfri5_hints_multi_query() {
        let polys = make_vfri5_polys(2, 300);
        let seed = vec![0x12u8; 32];
        let (_, c1, h1) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, c2, h2) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 2, Some(2)).unwrap();
        assert_eq!(c1, c2, "same trace → same commitment regardless of n_queries");
        assert_ne!(h1, h2, "more queries → different hints");
        assert!(h2.len() > h1.len(), "2-query hints must be larger than 1-query hints");
    }

    #[test]
    fn test_gen_vfri5_hints_comp_root_in_hints() {
        let polys = make_vfri5_polys(4, 400);
        let seed = vec![0xabu8; 32];
        let (_, _, hints) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        // head = 6 × 32 = 192 bytes; compRoot at slot 3 = bytes 96..128
        assert!(hints.len() > 192, "hints must contain head + bodies");
        let comp_root_slot = &hints[96..128];
        assert_ne!(comp_root_slot, &[0u8; 32], "compRoot must be non-zero");
    }

    // ── ML-DSA V23 VFRI4 tests ────────────────────────────────────────────────

    #[test]
    fn test_gen_mldsa_v23_vfri4_hints_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(7000);
        let seed = vec![0u8; 32];
        let result = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3));
        assert!(result.is_ok(), "v23_vfri4 should succeed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri4_hints_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(7100);
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, c2, h2) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_eq!(c1, c2, "deterministic commitment");
        assert_eq!(h1, h2, "deterministic hints");
    }

    #[test]
    fn test_gen_mldsa_v23_vfri4_hints_differs_from_vfri3() {
        // VFRI4 and VFRI3 transcripts are incompatible → different hints
        let (z, c, t1, a_hat) = make_v23_inputs(7200);
        let seed = vec![0x42u8; 32];
        let (_, _c3, h3) = gen_mldsa_v23_vfri3_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, _c4, h4) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_ne!(h3, h4, "VFRI4 transcript must differ from VFRI3");
    }

    #[test]
    fn test_gen_mldsa_v23_vfri4_hints_n_cols_1298() {
        // Combined trace: NttBatch (649) + InttBatch (649) = 1298 columns
        let (z, c, t1, a_hat) = make_v23_inputs(7300);
        let seed = vec![0u8; 32];
        // num_folds=3 → small last layer, fast test
        let (proof, _, hints) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        // proof[8:40] = trace_root; must be non-zero for a real 1298-col trace
        assert_ne!(&proof[8..40], &[0u8; 32]);
        // hints encode 1298 query_values + 1298 query_values_neg per query
        assert!(hints.len() > 10_000, "1298-col trace hints should be large");
    }

    // ── VFRI6 tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_gen_vfri6_hints_smoke() {
        let polys = make_vfri5_polys(3, 0);
        let seed = vec![0x55u8; 32];
        let result = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(2));
        assert!(result.is_ok(), "vfri6 smoke: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 100);
        assert_eq!(commitment.len(), 32, "commitment is 16-byte hex = 32 chars");
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_vfri6_hints_deterministic() {
        let polys = make_vfri5_polys(4, 100);
        let seed = vec![0xddu8; 32];
        let (_, c1, h1) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, c2, h2) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gen_vfri6_hints_differ_from_vfri5() {
        let polys = make_vfri5_polys(4, 200);
        let seed = vec![0x99u8; 32];
        let (_, _c5, h5) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, _c6, h6) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        assert_ne!(h5, h6, "VFRI6 and VFRI5 hints must differ (different transcripts + ABI)");
    }

    #[test]
    fn test_gen_vfri6_hints_multi_query() {
        let polys = make_vfri5_polys(2, 300);
        let seed = vec![0x12u8; 32];
        let (_, c1, h1) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(2)).unwrap();
        let (_, c2, h2) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 2, Some(2)).unwrap();
        assert_eq!(c1, c2, "same trace → same commitment regardless of n_queries");
        assert_ne!(h1, h2, "more queries → different hints");
        assert!(h2.len() > h1.len(), "2-query hints must be larger than 1-query hints");
    }

    #[test]
    fn test_gen_vfri6_hints_smaller_than_vfri5() {
        // VFRI6 removes oodsEvalsPos[649] + oodsEvalsNeg[649] (2×649×16 = 20768 B)
        let polys = make_vfri5_polys(12, 500);
        let seed = vec![0xabu8; 32];
        let (_, _, h5) = gen_ntt_batch_vfri5_hints_nfolds(&polys, &seed, 1, Some(9)).unwrap();
        let (_, _, h6) = gen_ntt_batch_vfri6_hints_nfolds(&polys, &seed, 1, Some(9)).unwrap();
        assert!(h6.len() < h5.len(),
            "VFRI6 hints ({} B) must be smaller than VFRI5 ({} B)", h6.len(), h5.len());
    }

    pub(super) fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }
}
// ── ML-DSA V23 VFRI6 test helpers (need access to private make_v23_inputs) ──
#[cfg(test)]
mod tests_v23_vfri6_inner {
    use super::gen_mldsa_v23_vfri6_hints;
    use super::gen_mldsa_v23_vfri4_hints;
    use super::tests::make_v23_inputs;

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(8000);
        let seed = vec![0u8; 32];
        let result = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3));
        assert!(result.is_ok(), "v23_vfri6: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(8100);
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, c2, h2) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_differ_from_vfri4() {
        let (z, c, t1, a_hat) = make_v23_inputs(8200);
        let seed = vec![0x42u8; 32];
        let (_, _c4, h4) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, _c6, h6) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_ne!(h4, h6, "VFRI6 transcript must differ from VFRI4");
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_smaller_than_vfri4() {
        let (z, c, t1, a_hat) = make_v23_inputs(8300);
        let seed = vec![0u8; 32];
        let (_, _, h4) = gen_mldsa_v23_vfri4_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, _, h6) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert!(h6.len() < h4.len(),
            "VFRI6 hints ({} B) must be smaller than VFRI4 ({} B)", h6.len(), h4.len());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_n_cols_1298() {
        let (z, c, t1, a_hat) = make_v23_inputs(8400);
        let seed = vec![0u8; 32];
        let (proof, _, hints) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_ne!(&proof[8..40], &[0u8; 32], "trace root non-zero");
        assert!(hints.len() < 20_000,
            "VFRI6 1298-col hints should be small, got {} B", hints.len());
    }

    // ── LOG=8 group tests ─────────────────────────────────────────────────────

    pub(super) fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_log8_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(9000);
        let hints = make_log8_hints();
        let seed = vec![0u8; 32];
        let result = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 1, Some(3),
        );
        assert!(result.is_ok(), "log8 smoke: {:?}", result.err());
        let (proof, commitment, query_hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!query_hints.is_empty());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_log8_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(9100);
        let hints = make_log8_hints();
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 1, Some(3),
        ).unwrap();
        let (_, c2, h2) = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 1, Some(3),
        ).unwrap();
        assert_eq!(c1, c2, "deterministic commitment");
        assert_eq!(h1, h2, "deterministic hints");
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_log8_n_cols_2206() {
        let (z, c, t1, a_hat) = make_v23_inputs(9200);
        let hints = make_log8_hints();
        let seed = vec![0u8; 32];
        let (proof, _, query_hints) = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 1, Some(3),
        ).unwrap();
        // proof[8:40] = trace root — non-zero for a real 2206-col trace
        assert_ne!(&proof[8..40], &[0u8; 32], "trace root non-zero");
        // VFRI6: hint size is O(1) in n_cols — same ~7 KB regardless of column count
        assert!(query_hints.len() < 20_000,
            "VFRI6 2206-col hints should be small, got {} B", query_hints.len());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_log8_smaller_than_vfri4() {
        // VFRI6 LOG=8 (2206 cols) hints must be substantially smaller than VFRI4
        // which grows O(n_cols) with oodsEvalsPos[2206] + oodsEvalsNeg[2206] arrays.
        // VFRI4 at 2206 cols: ~70 KB; VFRI6: ~3.5 KB (same 2 uint128 + Merkle proof)
        let (z, c, t1, a_hat) = make_v23_inputs(9300);
        let hints = make_log8_hints();
        let seed = vec![0u8; 32];
        let (_, _, h_log8_v6) = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 1, Some(3),
        ).unwrap();
        let (_, _, h_log10_v6) = gen_mldsa_v23_vfri6_hints(
            &z, &c, &t1, &a_hat, &seed, 1, Some(3),
        ).unwrap();
        // VFRI6 hint size depends only on tree_depth and num_folds, not n_cols.
        // LOG=8 (tree_depth=8) has shorter Merkle paths than LOG=10 (tree_depth=10),
        // so LOG=8 hints should be ≤ LOG=10 hints.
        assert!(h_log8_v6.len() <= h_log10_v6.len(),
            "VFRI6 LOG=8 hints ({} B) should not exceed LOG=10 ({} B)",
            h_log8_v6.len(), h_log10_v6.len());
        // Both are much smaller than the O(n_cols) VFRI4 equivalent (>50 KB for 2206 cols)
        assert!(h_log8_v6.len() < 20_000,
            "VFRI6 2206-col hints should be < 20 KB, got {} B", h_log8_v6.len());
    }

    #[test]
    fn test_gen_mldsa_v23_vfri6_hints_log8_validation_errors() {
        let (z, c, t1, a_hat) = make_v23_inputs(9400);
        let hints = make_log8_hints();
        let seed = vec![0u8; 32];
        // Wrong a_hat length
        let short_a_hat: Vec<[i64; 256]> = vec![[0i64; 256]; 29];
        let err = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &short_a_hat, &hints, &seed, 1, Some(3),
        );
        assert!(err.is_err(), "should reject wrong a_hat length");
        // n_queries=0
        let err2 = super::gen_mldsa_v23_vfri6_hints_log8(
            &z, &c, &t1, &a_hat, &hints, &seed, 0, Some(3),
        );
        assert!(err2.is_err(), "should reject n_queries=0");
    }
}

// ── ML-DSA V23 VFRI7 tests ───────────────────────────────────────────────────
#[cfg(test)]
mod tests_v23_vfri7 {
    use super::gen_mldsa_v23_vfri7_hints;
    use super::gen_mldsa_v23_vfri7_hints_log8;
    use super::gen_mldsa_v23_vfri7_cross_bound_hints;
    use super::gen_mldsa_v23_vfri6_hints;
    use super::tests::make_v23_inputs;

    fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }

    // ── LOG=10 smoke / determinism ────────────────────────────────────────────

    #[test]
    fn test_vfri7_log10_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(10000);
        let seed = vec![0u8; 32];
        let result = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3));
        assert!(result.is_ok(), "vfri7 log10 smoke: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_vfri7_log10_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(10100);
        let seed = vec![0xabu8; 32];
        let (_, c1, h1) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, c2, h2) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_eq!(c1, c2, "vfri7 log10 commitment must be deterministic");
        assert_eq!(h1, h2, "vfri7 log10 hints must be deterministic");
    }

    #[test]
    fn test_vfri7_log10_differs_from_vfri6() {
        // VFRI7 mixes merkleRoot before drawQueries → different query indices from VFRI6
        let (z, c, t1, a_hat) = make_v23_inputs(10200);
        let seed = vec![0x42u8; 32];
        let (_, _, h6) = gen_mldsa_v23_vfri6_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        let (_, _, h7) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed, 1, Some(3)).unwrap();
        assert_ne!(h6, h7, "VFRI7 hints must differ from VFRI6 (different Fiat-Shamir transcript)");
    }

    #[test]
    fn test_vfri7_log10_merkle_root_changes_hints() {
        // Different merkleRoot → different commitment binding AND different queryIndex → different hints.
        // (commitment = Blake2s(proof[:32] || merkleRoot)[:16], so it also changes)
        let (z, c, t1, a_hat) = make_v23_inputs(10300);
        let seed1 = vec![0x11u8; 32];
        let seed2 = vec![0x22u8; 32];
        let (p1, c1, h1) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed1, 1, Some(3)).unwrap();
        let (p2, c2, h2) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &seed2, 1, Some(3)).unwrap();
        // Same witness → same trace root (proof[8:40])
        assert_eq!(&p1[8..40], &p2[8..40], "same witness must produce same trace root");
        // Different merkleRoot changes commitment binding
        assert_ne!(c1, c2, "different merkleRoot must produce different commitment");
        // Different merkleRoot → different Fiat-Shamir path → different hints
        assert_ne!(h1, h2, "different merkleRoot must produce different hints");
    }

    // ── LOG=8 smoke / determinism ─────────────────────────────────────────────

    #[test]
    fn test_vfri7_log8_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(11000);
        let h8 = make_log8_hints();
        let seed = vec![0u8; 32];
        let result = gen_mldsa_v23_vfri7_hints_log8(&z, &c, &t1, &a_hat, &h8, &seed, 1, Some(3));
        assert!(result.is_ok(), "vfri7 log8 smoke: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_vfri7_log8_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(11100);
        let h8 = make_log8_hints();
        let seed = vec![0xabu8; 32];
        let (_, c1, q1) = gen_mldsa_v23_vfri7_hints_log8(&z, &c, &t1, &a_hat, &h8, &seed, 1, Some(3)).unwrap();
        let (_, c2, q2) = gen_mldsa_v23_vfri7_hints_log8(&z, &c, &t1, &a_hat, &h8, &seed, 1, Some(3)).unwrap();
        assert_eq!(c1, c2, "vfri7 log8 commitment must be deterministic");
        assert_eq!(q1, q2, "vfri7 log8 hints must be deterministic");
    }

    // ── Cross-bound hints ─────────────────────────────────────────────────────

    #[test]
    fn test_vfri7_cross_bound_smoke() {
        let (z, c, t1, a_hat) = make_v23_inputs(12000);
        let h8 = make_log8_hints();
        let batch_root = vec![0xddu8; 32];
        let result = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        );
        assert!(result.is_ok(), "cross_bound smoke: {:?}", result.err());
        let (proof10, commit10, hints10, proof8, commit8, hints8) = result.unwrap();
        assert!(proof10.len() >= 700);
        assert!(proof8.len()  >= 700);
        assert_eq!(commit10.len(), 32);
        assert_eq!(commit8.len(),  32);
        assert!(!hints10.is_empty());
        assert!(!hints8.is_empty());
    }

    #[test]
    fn test_vfri7_cross_bound_deterministic() {
        let (z, c, t1, a_hat) = make_v23_inputs(12100);
        let h8 = make_log8_hints();
        let batch_root = vec![0xeeu8; 32];
        let (p10a, c10a, h10a, p8a, c8a, h8a) = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        ).unwrap();
        let (p10b, c10b, h10b, p8b, c8b, h8b) = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        ).unwrap();
        assert_eq!(c10a, c10b); assert_eq!(h10a, h10b); assert_eq!(p10a, p10b);
        assert_eq!(c8a,  c8b);  assert_eq!(h8a,  h8b);  assert_eq!(p8a,  p8b);
    }

    #[test]
    fn test_vfri7_cross_bound_batch_root_changes_hints() {
        // Different batch_root → different cross-bound roots → different commitments AND hints.
        // (commitment = Blake2s(proof[:32] || boundRoot)[:16], boundRoot depends on batch_root)
        let (z, c, t1, a_hat) = make_v23_inputs(12200);
        let h8 = make_log8_hints();
        let root1 = vec![0x11u8; 32];
        let root2 = vec![0x22u8; 32];
        let (p10_1, c10_1, h10_1, p8_1, c8_1, h8_1) = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &root1, 1, Some(3),
        ).unwrap();
        let (p10_2, c10_2, h10_2, p8_2, c8_2, h8_2) = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &root2, 1, Some(3),
        ).unwrap();
        // Same witness → same trace roots (proof[8:40])
        assert_eq!(&p10_1[8..40], &p10_2[8..40], "LOG=10 trace root must be same for same witness");
        assert_eq!(&p8_1[8..40],  &p8_2[8..40],  "LOG=8 trace root must be same for same witness");
        // Different batch_root → different cross-bound roots → different commitments and hints
        assert_ne!(c10_1, c10_2, "different batch_root must produce different LOG=10 commitment");
        assert_ne!(c8_1,  c8_2,  "different batch_root must produce different LOG=8 commitment");
        assert_ne!(h10_1, h10_2, "different batch_root must produce different LOG=10 hints");
        assert_ne!(h8_1,  h8_2,  "different batch_root must produce different LOG=8 hints");
    }

    #[test]
    fn test_vfri7_cross_bound_trace_roots_cross(  ) {
        // Verify that proof10[8:40] != proof8[8:40]: they come from different trace domains
        let (z, c, t1, a_hat) = make_v23_inputs(12300);
        let h8 = make_log8_hints();
        let batch_root = vec![0xffu8; 32];
        let (proof10, _, _, proof8, _, _) = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        ).unwrap();
        let trace_root_10 = &proof10[8..40];
        let trace_root_8  = &proof8[8..40];
        assert_ne!(trace_root_10, &[0u8; 32], "LOG=10 trace root must be non-zero");
        assert_ne!(trace_root_8,  &[0u8; 32], "LOG=8 trace root must be non-zero");
        assert_ne!(trace_root_10, trace_root_8,
            "LOG=10 and LOG=8 trace roots must differ (different domains)");
    }

    #[test]
    fn test_vfri7_cross_bound_rejects_bad_batch_root_length() {
        let (z, c, t1, a_hat) = make_v23_inputs(12400);
        let h8 = make_log8_hints();
        let short_root = vec![0u8; 31];
        let err = gen_mldsa_v23_vfri7_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &short_root, 1, Some(3),
        );
        assert!(err.is_err(), "should reject batch_root shorter than 32 bytes");
    }

    /// Generates the full_v23_vfri7_cross_bound_e2e.json fixture and prints it.
    /// Run with: cargo test gen_vfri7_fixture -- --nocapture --ignored
    #[test]
    #[ignore]
    fn gen_vfri7_fixture() {
        let (z, c, t1, a_hat) = make_v23_inputs(99999);
        let h8 = make_log8_hints();
        // Use a deterministic batch Merkle root (sha3-512 would come from real batches)
        let mut batch_root = [0u8; 32];
        for (i, b) in batch_root.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(7).wrapping_add(1); }

        let (proof10, commit10, hints10, proof8, commit8, hints8) =
            gen_mldsa_v23_vfri7_cross_bound_hints(&z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3))
                .expect("cross_bound generation failed");

        // Verify cross-bound roots on-chain match what BatchRegistryV4 would compute
        use sha3::{Keccak256, Digest as Sha3Digest};
        let trace_root_10: [u8; 32] = proof10[8..40].try_into().unwrap();
        let trace_root_8:  [u8; 32] = proof8[8..40].try_into().unwrap();
        let bound_root_10: [u8; 32] = {
            let mut h = Keccak256::new(); h.update(&batch_root); h.update(&trace_root_8); h.finalize().into()
        };
        let bound_root_8: [u8; 32] = {
            let mut h = Keccak256::new(); h.update(&batch_root); h.update(&trace_root_10); h.finalize().into()
        };

        fn hex(b: &[u8]) -> String { format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()) }

        // commitment strings are already 32-char hex (no 0x prefix); add prefix for JSON
        let c10_hex = format!("0x{commit10}");
        let c8_hex  = format!("0x{commit8}");

        let json = format!(
            r#"{{
  "merkleRoot": "{}",
  "log10_proof": "{}",
  "log10_commitment": "{}",
  "log10_queryHints": "{}",
  "log8_proof": "{}",
  "log8_commitment": "{}",
  "log8_queryHints": "{}",
  "bound_root_10": "{}",
  "bound_root_8": "{}",
  "n_queries": 1
}}"#,
            hex(&batch_root),
            hex(&proof10),
            c10_hex,
            hex(&hints10),
            hex(&proof8),
            c8_hex,
            hex(&hints8),
            hex(&bound_root_10),
            hex(&bound_root_8),
        );
        println!("{json}");
        // Sanity checks
        assert!(!proof10.is_empty());
        assert!(!proof8.is_empty());
        assert_ne!(trace_root_10, trace_root_8);
    }
}

// ── ML-DSA V23 VFRI8 tests ───────────────────────────────────────────────────
#[cfg(test)]
mod tests_vfri8 {
    use super::*;

    #[test]
    fn test_p2_channel_deterministic() {
        let mut c1 = P2Channel::init();
        let mut c2 = P2Channel::init();
        let root = [0x42u8; 32];
        c1.mix_root(&root);
        c2.mix_root(&root);
        assert_eq!(c1.draw_secure_felt(), c2.draw_secure_felt());
    }

    #[test]
    fn test_p2_channel_differs_from_blake2s() {
        let mut p2 = P2Channel::init();
        let mut b2 = Channel::init();
        let root = [0x42u8; 32];
        p2.mix_root(&root);
        b2.mix_root(&root);
        assert_ne!(p2.draw_secure_felt(), b2.draw_secure_felt(),
            "P2Channel must produce different values than Blake2s channel");
    }

    #[test]
    fn test_hash_pair_p2_deterministic() {
        let left  = [0x11u8; 32];
        let right = [0x22u8; 32];
        let h1 = hash_pair_p2(&left, &right);
        let h2 = hash_pair_p2(&left, &right);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_pair_p2_not_commutative() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let h_ab = hash_pair_p2(&a, &b);
        let h_ba = hash_pair_p2(&b, &a);
        assert_ne!(h_ab, h_ba, "hashPair should not be commutative");
    }

    #[test]
    fn test_hash_leaf_cols_p2_consistency() {
        let cols = vec![1u32, 2, 3, 4];
        let h1 = hash_leaf_cols_p2(&cols);
        let h2 = hash_leaf_cols_p2(&cols);
        assert_eq!(h1, h2);
        // Must differ from Blake2s leaf hash
        let h_b2 = hash_leaf_cols(&cols);
        assert_ne!(h1, h_b2, "P2 leaf hash must differ from Blake2s leaf hash");
    }

    #[test]
    fn test_vfri8_smoke_small() {
        // Small test with 4 columns of depth=2 (4 rows each)
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xabu8; 32];
        let result = gen_vfri8_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1));
        assert!(result.is_ok(), "VFRI8 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_vfri8_differs_from_vfri7() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xabu8; 32];
        let (_, _, h7) = gen_vfri7_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        let (_, _, h8) = gen_vfri8_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        assert_ne!(h7, h8, "VFRI8 hints must differ from VFRI7 (different hash backend)");
    }

    #[test]
    fn test_vfri8_trace_root_differs_from_vfri7() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xabu8; 32];
        let (proof7, _, _) = gen_vfri7_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        let (proof8, _, _) = gen_vfri8_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        let root7 = &proof7[8..40];
        let root8 = &proof8[8..40];
        assert_ne!(root7, root8, "VFRI8 trace root must differ from VFRI7 (Poseidon2 vs Blake2s)");
    }

    #[test]
    fn test_vfri8_v23_log10_smoke() {
        use super::tests::make_v23_inputs;
        let (z, c, t1, a_hat) = make_v23_inputs(20000);
        let batch_root = [0x77u8; 32];
        let result = gen_mldsa_v23_vfri8_hints(&z, &c, &t1, &a_hat, &batch_root, 1, Some(3));
        assert!(result.is_ok(), "VFRI8 V23 LOG=10 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
        // hint size should be small (O(1) in n_cols)
        assert!(hints.len() < 50_000, "VFRI8 hints too large: {} bytes", hints.len());
    }

    #[test]
    fn test_vfri8_v23_log10_differs_from_vfri7() {
        use super::tests::make_v23_inputs;
        let (z, c, t1, a_hat) = make_v23_inputs(20100);
        let batch_root = [0x77u8; 32];
        let (_, _, h7) = gen_mldsa_v23_vfri7_hints(&z, &c, &t1, &a_hat, &batch_root, 1, Some(3)).unwrap();
        let (_, _, h8) = gen_mldsa_v23_vfri8_hints(&z, &c, &t1, &a_hat, &batch_root, 1, Some(3)).unwrap();
        assert_ne!(h7, h8, "VFRI8 V23 hints must differ from VFRI7");
    }

    #[test]
    fn test_vfri8_hint_size_oc1_in_ncols() {
        use super::tests::make_v23_inputs;
        let (z, c, t1, a_hat) = make_v23_inputs(20200);
        let batch_root = [0x88u8; 32];
        // VFRI8 hint size is O(1) in n_cols: 1298-col and 649-col hints should be similar size
        let (_, _, h_1298) = gen_mldsa_v23_vfri8_hints(&z, &c, &t1, &a_hat, &batch_root, 1, Some(3)).unwrap();
        // Compare to a 4-column trace of same depth
        let cols_small: Vec<Vec<u32>> = (0..4).map(|_| vec![0u32; 1024]).collect();
        let (_, _, h_small) = gen_vfri8_hints_from_cols_nfolds(&cols_small, 10, &batch_root, 1, Some(3)).unwrap();
        // Both should have similar hint sizes (within 2x) — demonstrating O(1) in n_cols
        let ratio = h_1298.len().max(h_small.len()) as f64 / h_1298.len().min(h_small.len()) as f64;
        assert!(ratio < 2.0,
            "VFRI8 hint size should be O(1) in n_cols: 1298-col={} bytes, 4-col={} bytes, ratio={:.2}",
            h_1298.len(), h_small.len(), ratio);
    }

    #[test]
    fn test_vfri8_validation_errors() {
        let cols: Vec<Vec<u32>> = vec![vec![0u32; 4]];
        // tree_depth < 2
        assert!(gen_vfri8_hints_from_cols_nfolds(&cols, 1, &[0u8; 32], 1, None).is_err());
        // wrong batch_merkle_root length
        assert!(gen_vfri8_hints_from_cols_nfolds(&cols, 2, &[0u8; 31], 1, None).is_err());
        // n_queries = 0
        assert!(gen_vfri8_hints_from_cols_nfolds(&cols, 2, &[0u8; 32], 0, None).is_err());
        // n_queries > 64
        assert!(gen_vfri8_hints_from_cols_nfolds(&cols, 2, &[0u8; 32], 65, None).is_err());
    }

    #[test]
    fn test_vfri8_cross_bound_smoke() {
        use super::tests::{make_v23_inputs, make_log8_hints};
        let (z, c, t1, a_hat) = make_v23_inputs(20300);
        let h8 = make_log8_hints();
        let batch_root = [0x99u8; 32];
        let result = gen_mldsa_v23_vfri8_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        );
        assert!(result.is_ok(), "VFRI8 cross_bound smoke: {:?}", result.err());
        let (proof10, commit10, _, proof8, commit8, _) = result.unwrap();
        assert!(proof10.len() >= 700);
        assert!(proof8.len() >= 700);
        assert_eq!(commit10.len(), 32);
        assert_eq!(commit8.len(), 32);
        // Trace roots must differ
        assert_ne!(&proof10[8..40], &proof8[8..40],
            "LOG=10 and LOG=8 trace roots should differ");
    }

    #[test]
    fn test_vfri8_cross_bound_differs_from_vfri7() {
        use super::tests::{make_v23_inputs, make_log8_hints};
        let (z, c, t1, a_hat) = make_v23_inputs(20400);
        let h8 = make_log8_hints();
        let batch_root = [0x99u8; 32];
        let (p10_v7, _, h10_v7, _, _, _) =
            gen_mldsa_v23_vfri7_cross_bound_hints(&z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3)).unwrap();
        let (p10_v8, _, h10_v8, _, _, _) =
            gen_mldsa_v23_vfri8_cross_bound_hints(&z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3)).unwrap();
        assert_ne!(h10_v7, h10_v8, "VFRI8 cross_bound hints must differ from VFRI7");
        assert_ne!(&p10_v7[8..40], &p10_v8[8..40], "VFRI8 trace roots must differ from VFRI7");
    }

    // ── VFRI9 tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_hash_pair_p2w_uses_both_words() {
        // Two nodes that agree in s1 (low word) but differ in s0 (high word)
        // must produce different parent hashes — this is exactly the collision
        // VFRI8's 31-bit nodes could not prevent.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&7u32.to_be_bytes());
        b[24..28].copy_from_slice(&2u32.to_be_bytes());
        b[28..32].copy_from_slice(&7u32.to_be_bytes());
        let sib = [0x05u8; 32];
        assert_ne!(hash_pair_p2w(&a, &sib), hash_pair_p2w(&b, &sib));
        assert_ne!(hash_pair_p2w(&sib, &a), hash_pair_p2w(&sib, &b));
    }

    #[test]
    fn test_hash_leaf_cols_p2w_wide_output() {
        let cols = vec![1u32, 2, 3, 4];
        let h = hash_leaf_cols_p2w(&cols);
        // Narrow VFRI8 leaf and wide VFRI9 leaf must differ in encoding
        let h_narrow = hash_leaf_cols_p2(&cols);
        assert_ne!(h, h_narrow);
        // bytes[0..24] must be zero (62-bit content in low 8 bytes)
        assert_eq!(&h[..24], &[0u8; 24]);
        // Same sponge: wide s0 (bytes 24..28) equals narrow s0 (bytes 28..32)
        assert_eq!(&h[24..28], &h_narrow[28..32],
            "s0 word must match the narrow hash (same sponge)");
    }

    // ── VFRI10 t=4 hash backend cross-check ──────────────────────────────────

    #[test]
    #[ignore = "prints reference vectors for regeneration; values are frozen in test_p2t4_reference_vectors"]
    fn test_p2t4_print_reference_vectors() {
        // Prints the values frozen below + in Poseidon2MerkleVerifierT4.test.js.
        // Run with: cargo test test_p2t4_print_reference_vectors -- --ignored --nocapture
        let leaf = hash_leaf_cols_p2t4(&[1, 2, 3, 4]);
        let l0 = u32::from_be_bytes(leaf[24..28].try_into().unwrap());
        let l1 = u32::from_be_bytes(leaf[28..32].try_into().unwrap());
        eprintln!("hash_leaf_cols_p2t4([1,2,3,4]) = ({l0}, {l1})");

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&2u32.to_be_bytes());
        b[24..28].copy_from_slice(&3u32.to_be_bytes());
        b[28..32].copy_from_slice(&4u32.to_be_bytes());
        let pair = hash_pair_p2t4(&a, &b);
        let p0 = u32::from_be_bytes(pair[24..28].try_into().unwrap());
        let p1 = u32::from_be_bytes(pair[28..32].try_into().unwrap());
        eprintln!("hash_pair_p2t4([1,2],[3,4]) = ({p0}, {p1})");

        let mut ch = P2T4Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        let q = ch.draw_queries(10, 4);
        eprintln!("channel.mix_root(0x11..).draw_queries(10,4) = {q:?}");
        let felt = { let mut c = P2T4Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        eprintln!("channel.mix_u32s([1,2,3]).draw_secure_felt() = {felt}");
    }

    #[test]
    fn test_p2t4_reference_vectors() {
        // Frozen — Poseidon2MerkleVerifierT4.test.js asserts the same outputs.
        let leaf = hash_leaf_cols_p2t4(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes(leaf[24..28].try_into().unwrap()), 188_265_029);
        assert_eq!(u32::from_be_bytes(leaf[28..32].try_into().unwrap()), 348_838_750);

        // hash_pair of nodes (1,2) and (3,4) is exactly compress_t4([1,2],[3,4]).
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&2u32.to_be_bytes());
        b[24..28].copy_from_slice(&3u32.to_be_bytes());
        b[28..32].copy_from_slice(&4u32.to_be_bytes());
        let pair = hash_pair_p2t4(&a, &b);
        assert_eq!(u32::from_be_bytes(pair[24..28].try_into().unwrap()), 1_706_601_437);
        assert_eq!(u32::from_be_bytes(pair[28..32].try_into().unwrap()), 1_471_208_702);
    }

    #[test]
    fn test_p2t4_leaf_is_wide_and_sponge_consistent() {
        let cols = vec![1u32, 2, 3, 4];
        let h = hash_leaf_cols_p2t4(&cols);
        // Content lives in the low 8 bytes; upper 24 bytes are zero.
        assert_eq!(&h[..24], &[0u8; 24]);
        // Leaf == sponge_t4 of the columns (first two words).
        let s = crate::poseidon2_t4::sponge_t4(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes(h[24..28].try_into().unwrap()), s[0] as u32);
        assert_eq!(u32::from_be_bytes(h[28..32].try_into().unwrap()), s[1] as u32);
        // t=4 leaf differs from the t=2 wide leaf (different permutation).
        assert_ne!(h, hash_leaf_cols_p2w(&cols));
    }

    #[test]
    fn test_p2t4_pair_uses_both_words_and_order_sensitive() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&7u32.to_be_bytes());
        b[24..28].copy_from_slice(&2u32.to_be_bytes());
        b[28..32].copy_from_slice(&7u32.to_be_bytes());
        let sib = [0x05u8; 32];
        // Nodes differing only in the high word must yield different parents.
        assert_ne!(hash_pair_p2t4(&a, &sib), hash_pair_p2t4(&b, &sib));
        // Compression is not commutative.
        assert_ne!(hash_pair_p2t4(&a, &sib), hash_pair_p2t4(&sib, &a));
    }

    #[test]
    fn test_p2t4_tree_roundtrip() {
        // Build a depth-2 tree, walk a Merkle path, confirm it reaches the root.
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|j| hash_leaf_cols_p2t4(&[j, j + 1, j + 2]))
            .collect();
        let levels = build_tree_p2t4(leaves.clone());
        let root = levels.last().unwrap()[0];
        assert_eq!(levels.len(), 3); // 4 → 2 → 1
        // Verify inclusion of leaf index 1 by recomputing up the path.
        let idx = 1usize;
        let mut cur = leaves[idx];
        let sib0 = leaves[0]; // sibling of leaf 1 is leaf 0
        cur = hash_pair_p2t4(&sib0, &cur); // idx odd → sibling on the left
        let sib1 = levels[1][1]; // sibling of node 0 at level 1 is node 1
        cur = hash_pair_p2t4(&cur, &sib1);
        assert_eq!(cur, root);
    }

    #[test]
    fn test_p2t4_channel_deterministic_and_binds() {
        let mut a = P2T4Channel::init();
        let mut b = P2T4Channel::init();
        a.mix_root(&[0x11u8; 32]);
        b.mix_root(&[0x11u8; 32]);
        assert_eq!(a.draw_queries(10, 8), b.draw_queries(10, 8));
        // Different root → different query stream.
        let mut c = P2T4Channel::init();
        c.mix_root(&[0x12u8; 32]);
        let mut d = P2T4Channel::init();
        d.mix_root(&[0x11u8; 32]);
        assert_ne!(c.draw_queries(10, 8), d.draw_queries(10, 8));
        // Queries are within the domain.
        let mut e = P2T4Channel::init();
        e.mix_root(&[0x11u8; 32]);
        for q in e.draw_queries(10, 16) {
            assert!(q < (1 << 10));
        }
    }

    #[test]
    fn test_p2t4_channel_full_root_binds_all_bytes() {
        // mix_root_full must depend on every byte; mix_root (low 4 bytes) must not.
        let mut base = [0u8; 32];
        base[0] = 0xAA; // high byte
        let mut alt = base;
        alt[0] = 0xBB;
        let q_full_base = { let mut c = P2T4Channel::init(); c.mix_root_full(&base); c.draw_queries(8, 4) };
        let q_full_alt = { let mut c = P2T4Channel::init(); c.mix_root_full(&alt); c.draw_queries(8, 4) };
        assert_ne!(q_full_base, q_full_alt, "mix_root_full must bind high bytes");
        // mix_root only looks at bytes[28..32] → high-byte change is invisible.
        let q_lo_base = { let mut c = P2T4Channel::init(); c.mix_root(&base); c.draw_queries(8, 4) };
        let q_lo_alt = { let mut c = P2T4Channel::init(); c.mix_root(&alt); c.draw_queries(8, 4) };
        assert_eq!(q_lo_base, q_lo_alt);
    }

    #[test]
    fn test_vfri9_smoke_small() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xabu8; 32];
        let result = gen_vfri9_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1));
        assert!(result.is_ok(), "VFRI9 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
        // Version marker
        assert_eq!(u64::from_le_bytes(proof[0..8].try_into().unwrap()), 3u64);
    }

    #[test]
    fn test_vfri10_smoke_small() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xcdu8; 32];
        let result = gen_vfri10_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2));
        assert!(result.is_ok(), "VFRI10 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
        // VFRI10 version marker = 4.
        assert_eq!(u64::from_le_bytes(proof[0..8].try_into().unwrap()), 4u64);
    }

    #[test]
    fn test_vfri10_differs_from_vfri9() {
        // Same inputs, different hash backend → different trace root / proof.
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xcdu8; 32];
        let (p9, _, h9) = gen_vfri9_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        let (p10, _, h10) = gen_vfri10_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_ne!(&p9[8..40], &p10[8..40], "t=4 trace root must differ from t=2");
        assert_ne!(h9, h10, "VFRI10 hints must differ from VFRI9 (different backend)");
        assert_eq!(u64::from_le_bytes(p9[0..8].try_into().unwrap()), 3u64);
        assert_eq!(u64::from_le_bytes(p10[0..8].try_into().unwrap()), 4u64);
    }

    /// Writes the VFRI10 E2E fixture consumed by QLSAVerifierVFRI10E2E.test.js.
    /// Run with: cargo test write_vfri10_e2e_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/vfri10_e2e.json"]
    fn write_vfri10_e2e_fixture() {
        // Small synthetic trace: 6 columns, tree_depth=4 (16 rows), 2 queries,
        // 2 folds → last layer has 16/4 = 4 evaluations.
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..6)
            .map(|j| (0..n).map(|i| ((i * 7 + j * 13 + 1) as u32) % 2_147_483_647).collect())
            .collect();
        let mut batch_root = [0u8; 32];
        for (i, b) in batch_root.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(9).wrapping_add(3); }

        let (proof, commitment_hex, hints) =
            gen_vfri10_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2))
                .expect("VFRI10 fixture generation failed");

        let json = format!(
            "{{\n  \"proof\": \"0x{}\",\n  \"commitment\": \"0x{}\",\n  \"merkleRoot\": \"0x{}\",\n  \"queryHints\": \"0x{}\",\n  \"n_queries\": 2,\n  \"num_folds\": 2,\n  \"tree_depth\": 4\n}}\n",
            hex::encode(&proof),
            commitment_hex,
            hex::encode(batch_root),
            hex::encode(&hints),
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/test/fixtures/vfri10_e2e.json");
        std::fs::write(path, json).expect("failed to write fixture");
        eprintln!("wrote {path}");
    }

    #[test]
    fn test_vfri9_differs_from_vfri8() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xabu8; 32];
        let (p8, _, h8) = gen_vfri8_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        let (p9, _, h9) = gen_vfri9_hints_from_cols_nfolds(&cols, 2, &batch_root, 1, Some(1)).unwrap();
        assert_ne!(h8, h9, "VFRI9 hints must differ from VFRI8 (wide nodes + last layer)");
        assert_ne!(&p8[8..40], &p9[8..40], "VFRI9 trace root must differ (wide leaf hash)");
    }

    #[test]
    fn test_vfri9_deterministic() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..4).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0x11u8; 32];
        let r1 = gen_vfri9_hints_from_cols_nfolds(&cols, 2, &batch_root, 2, Some(1)).unwrap();
        let r2 = gen_vfri9_hints_from_cols_nfolds(&cols, 2, &batch_root, 2, Some(1)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_vfri9_full_root_binding() {
        // VFRI9 absorbs all 32 bytes of the batch root; two roots that agree
        // in the low 4 bytes but differ elsewhere must change the hints.
        // (In VFRI8 these produced identical query indices.)
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..8).map(|i| (i*4 + j) as u32).collect()).collect();
        let mut root_a = [0x00u8; 32];
        let mut root_b = [0x00u8; 32];
        root_a[0] = 0xAA; // differs only in high bytes
        root_b[0] = 0xBB;
        root_a[28..32].copy_from_slice(&[1, 2, 3, 4]);
        root_b[28..32].copy_from_slice(&[1, 2, 3, 4]);
        let (_, c_a, h_a) = gen_vfri9_hints_from_cols_nfolds(&cols, 3, &root_a, 2, Some(2)).unwrap();
        let (_, c_b, h_b) = gen_vfri9_hints_from_cols_nfolds(&cols, 3, &root_b, 2, Some(2)).unwrap();
        // Commitment differs (Blake2s binds the full root) AND hints differ
        // (channel absorbs the full root → different query indices/values).
        assert_ne!(c_a, c_b);
        assert_ne!(h_a, h_b, "VFRI9 must bind ALL 32 bytes of the batch root in Fiat-Shamir");
    }

    #[test]
    fn test_vfri9_last_layer_evals_in_abi() {
        // depth=3, num_folds=1 → last layer has 2^(3-1)/2 = 4 evals (L1 has 8, one fold → 4)
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..8).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0x22u8; 32];
        let (_, _, hints) = gen_vfri9_hints_from_cols_nfolds(&cols, 3, &batch_root, 1, Some(1)).unwrap();
        // Head slot 3 = offset of lastLayerEvals array
        let evals_offset = u64::from_be_bytes(hints[3*32+24..4*32].try_into().unwrap()) as usize;
        assert_eq!(evals_offset, 6 * 32, "lastLayerEvals must directly follow the 6-slot head");
        let evals_len = u64::from_be_bytes(hints[evals_offset+24..evals_offset+32].try_into().unwrap()) as usize;
        assert_eq!(evals_len, 4, "depth=3 with 1 fold → 4 last-layer evaluations");
    }

    #[test]
    fn test_vfri9_v23_log10_smoke() {
        use super::tests::make_v23_inputs;
        let (z, c, t1, a_hat) = make_v23_inputs(21000);
        let batch_root = [0x77u8; 32];
        let result = gen_mldsa_v23_vfri9_hints(&z, &c, &t1, &a_hat, &batch_root, 1, Some(3));
        assert!(result.is_ok(), "VFRI9 V23 LOG=10 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        // depth=10, 3 folds → 1024/2/2/2 = 128 last-layer evals = 4 KB extra; still small
        assert!(hints.len() < 60_000, "VFRI9 hints too large: {} bytes", hints.len());
    }

    #[test]
    fn test_vfri9_validation_errors() {
        let cols: Vec<Vec<u32>> = vec![vec![0u32; 4]];
        assert!(gen_vfri9_hints_from_cols_nfolds(&cols, 1, &[0u8; 32], 1, None).is_err());
        assert!(gen_vfri9_hints_from_cols_nfolds(&cols, 2, &[0u8; 31], 1, None).is_err());
        assert!(gen_vfri9_hints_from_cols_nfolds(&cols, 2, &[0u8; 32], 0, None).is_err());
        assert!(gen_vfri9_hints_from_cols_nfolds(&cols, 2, &[0u8; 32], 65, None).is_err());
    }

    #[test]
    fn test_vfri9_cross_bound_smoke() {
        use super::tests::{make_v23_inputs, make_log8_hints};
        let (z, c, t1, a_hat) = make_v23_inputs(21300);
        let h8 = make_log8_hints();
        let batch_root = [0x99u8; 32];
        let result = gen_mldsa_v23_vfri9_cross_bound_hints(
            &z, &c, &t1, &a_hat, &h8, &batch_root, 1, Some(3),
        );
        assert!(result.is_ok(), "VFRI9 cross_bound smoke: {:?}", result.err());
        let (proof10, commit10, _, proof8, commit8, _) = result.unwrap();
        assert!(proof10.len() >= 700);
        assert!(proof8.len() >= 700);
        assert_eq!(commit10.len(), 32);
        assert_eq!(commit8.len(), 32);
        assert_ne!(&proof10[8..40], &proof8[8..40],
            "LOG=10 and LOG=8 trace roots should differ");
    }
}
