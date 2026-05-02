use std::io::{self, Read};

use serde::{Deserialize, Serialize};

/// Input JSON for the `prove` command.
#[derive(Deserialize)]
struct ProveInput {
    leaves: Vec<u64>,
}

// ── mldsa_batch ──────────────────────────────────────────────────────────────

/// One entry in a ML-DSA batch (all fields base64-encoded).
#[derive(Deserialize)]
struct MldsaEntry {
    pk:  String,
    msg: String,
    sig: String,
}

/// Input JSON for the `mldsa_batch` command.
#[derive(Deserialize)]
struct MldsaBatchInput {
    entries: Vec<MldsaEntry>,
}

/// Output JSON for the `mldsa_batch` command.
#[derive(Serialize)]
struct MldsaBatchOutput {
    proof:      String, // base64-encoded STARK proof
    commitment: String, // 8-char little-endian hex
    log_size:   u32,
    verified:   usize,  // number of valid signatures included in proof
    rejected:   usize,  // number of invalid signatures skipped
}

/// Output JSON for the `prove` command.
#[derive(Serialize)]
struct ProveOutput {
    proof: String,      // base64-encoded proof bytes
    commitment: String, // 8-char little-endian hex (4 bytes, M31)
    log_size: u32,
}

/// Input JSON for the `verify` command.
#[derive(Deserialize)]
struct VerifyInput {
    proof: String,
    commitment: String,
    log_size: u32,
}

/// Output JSON for the `verify` command.
#[derive(Serialize)]
struct VerifyOutput {
    valid: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: qlsa-stark-stwo <prove|verify|mldsa_batch|prove_p2|verify_p2|merkle_prove|merkle_verify>");
        std::process::exit(1);
    }

    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {e}");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "prove" => {
            let req: ProveInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for prove: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::prove_hash_chain(&req.leaves) {
                Ok((proof_bytes, commitment, log_size)) => {
                    let out = ProveOutput {
                        proof: base64_encode(&proof_bytes),
                        commitment,
                        log_size,
                    };
                    match serde_json::to_string(&out) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("prove error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            let req: VerifyInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for verify: {e}");
                    std::process::exit(1);
                }
            };
            let proof_bytes = match base64_decode(&req.proof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("invalid base64 proof: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::verify_hash_chain(&proof_bytes, &req.commitment, req.log_size) {
                Ok(valid) => {
                    match serde_json::to_string(&VerifyOutput { valid }) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("verify error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "mldsa_batch" => {
            let req: MldsaBatchInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for mldsa_batch: {e}");
                    std::process::exit(1);
                }
            };
            // Decode base64 fields.
            let entries: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = req
                .entries
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let pk  = base64_decode(&e.pk).unwrap_or_else(|_| {
                        eprintln!("entry[{i}]: invalid pk base64");
                        std::process::exit(1);
                    });
                    let msg = base64_decode(&e.msg).unwrap_or_else(|_| {
                        eprintln!("entry[{i}]: invalid msg base64");
                        std::process::exit(1);
                    });
                    let sig = base64_decode(&e.sig).unwrap_or_else(|_| {
                        eprintln!("entry[{i}]: invalid sig base64");
                        std::process::exit(1);
                    });
                    (pk, msg, sig)
                })
                .collect();

            match qlsa_stark_stwo::prove_mldsa_batch(&entries) {
                Ok((proof_bytes, commitment, log_size, verified, rejected)) => {
                    let out = MldsaBatchOutput {
                        proof: base64_encode(&proof_bytes),
                        commitment,
                        log_size,
                        verified,
                        rejected,
                    };
                    match serde_json::to_string(&out) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("mldsa_batch error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "prove_p2" => {
            let req: ProveInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for prove_p2: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::prove_hash_chain_poseidon2(&req.leaves) {
                Ok((proof_bytes, commitment, log_size)) => {
                    let out = ProveOutput {
                        proof: base64_encode(&proof_bytes),
                        commitment,
                        log_size,
                    };
                    match serde_json::to_string(&out) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("prove_p2 error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "verify_p2" => {
            let req: VerifyInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for verify_p2: {e}");
                    std::process::exit(1);
                }
            };
            let proof_bytes = match base64_decode(&req.proof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("invalid base64 proof: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::verify_hash_chain_poseidon2(&proof_bytes, &req.commitment, req.log_size) {
                Ok(valid) => {
                    match serde_json::to_string(&VerifyOutput { valid }) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("verify_p2 error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "merkle_prove" => {
            let req: ProveInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for merkle_prove: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::prove_merkle_root(&req.leaves) {
                Ok((proof_bytes, commitment, log_size)) => {
                    let out = ProveOutput {
                        proof: base64_encode(&proof_bytes),
                        commitment,
                        log_size,
                    };
                    match serde_json::to_string(&out) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("merkle_prove error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "merkle_verify" => {
            let req: VerifyInput = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid JSON input for merkle_verify: {e}");
                    std::process::exit(1);
                }
            };
            let proof_bytes = match base64_decode(&req.proof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("invalid base64 proof: {e}");
                    std::process::exit(1);
                }
            };
            match qlsa_stark_stwo::verify_merkle_root(&proof_bytes, &req.commitment, req.log_size) {
                Ok(valid) => {
                    match serde_json::to_string(&VerifyOutput { valid }) {
                        Ok(s) => println!("{s}"),
                        Err(e) => { eprintln!("serialization error: {e}"); std::process::exit(1); }
                    }
                }
                Err(e) => {
                    eprintln!("merkle_verify error: {e}");
                    std::process::exit(1);
                }
            }
        }
        cmd => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
    }
}

// Minimal base64 helpers using the `base64` crate alphabet manually,
// or re-using the standard STANDARD alphabet via the base64 crate dependency.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((combined >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(combined & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let mut table = [0xFFu8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[c as usize] = i as u8;
    }
    if s.len() % 4 != 0 {
        return Err("base64 length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.as_bytes().chunks(4) {
        let c0 = table[chunk[0] as usize];
        let c1 = table[chunk[1] as usize];
        let c2 = table[chunk[2] as usize];
        let c3 = table[chunk[3] as usize];
        if c0 == 0xFF || c1 == 0xFF {
            return Err("invalid base64 character".into());
        }
        out.push((c0 << 2) | (c1 >> 4));
        if chunk[2] != b'=' {
            if c2 == 0xFF { return Err("invalid base64 character".into()); }
            out.push((c1 << 4) | (c2 >> 2));
        }
        if chunk[3] != b'=' {
            if c3 == 0xFF { return Err("invalid base64 character".into()); }
            out.push((c2 << 6) | c3);
        }
    }
    Ok(out)
}
