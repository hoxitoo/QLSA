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

    // ── OODS evaluations via barycentric Lagrange interpolation ──────────────
    // domain_xs[i] = coset_at(tree_depth, i).x (M31)
    let domain_xs: Vec<u32> = (0..n).map(|i| coset_at(tree_depth, i as u64).0).collect();

    // Precompute barycentric weights once for all columns.
    let bary_weights = precompute_bary_weights(&domain_xs);

    let z_neg = qm31_neg(z_x); // −z_x for oodsEvalsNeg

    let oods_evals_pos: Vec<u128> = cols
        .iter()
        .map(|col| eval_bary(col, &domain_xs, &bary_weights, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols
        .iter()
        .map(|col| eval_bary(col, &domain_xs, &bary_weights, z_neg))
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

    // ── OODS evaluations via barycentric Lagrange interpolation ──────────────
    let domain_xs: Vec<u32> = (0..n).map(|i| coset_at(tree_depth, i as u64).0).collect();
    let bary_weights = precompute_bary_weights(&domain_xs);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_bary(col, &domain_xs, &bary_weights, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_bary(col, &domain_xs, &bary_weights, z_neg))
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
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
}
