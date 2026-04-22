use std::io::{self, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// JSON I/O types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProveInput {
    leaves: Vec<u64>,
}

#[derive(Serialize)]
struct ProveOutput {
    proof:      String,  // base64-encoded proof bytes
    commitment: String,  // hex-encoded field element (16 chars)
}

#[derive(Deserialize)]
struct VerifyInput {
    proof:      String,  // base64
    commitment: String,  // hex
}

#[derive(Serialize)]
struct VerifyOutput {
    valid: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: qlsa-stark <prove|verify>");
        std::process::exit(1);
    }

    let mut stdin_buf = String::new();
    io::stdin()
        .read_to_string(&mut stdin_buf)
        .expect("failed to read stdin");

    match args[1].as_str() {
        "prove"  => cmd_prove(&stdin_buf),
        "verify" => cmd_verify(&stdin_buf),
        cmd      => {
            eprintln!("Unknown command '{cmd}'. Use prove or verify.");
            std::process::exit(1);
        }
    }
}

fn cmd_prove(input_json: &str) {
    let input: ProveInput = serde_json::from_str(input_json).unwrap_or_else(|e| {
        eprintln!("prove: invalid JSON input: {e}");
        std::process::exit(1);
    });

    if input.leaves.is_empty() {
        eprintln!("prove: leaves list must not be empty");
        std::process::exit(1);
    }

    match qlsa_stark::prove(input.leaves) {
        Ok((proof_bytes, commitment_hex)) => {
            let out = ProveOutput {
                proof:      B64.encode(&proof_bytes),
                commitment: commitment_hex,
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Err(e) => {
            eprintln!("prove error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_verify(input_json: &str) {
    let input: VerifyInput = serde_json::from_str(input_json).unwrap_or_else(|e| {
        eprintln!("verify: invalid JSON input: {e}");
        std::process::exit(1);
    });

    let proof_bytes = B64.decode(&input.proof).unwrap_or_else(|e| {
        eprintln!("verify: invalid base64 proof: {e}");
        std::process::exit(1);
    });

    match qlsa_stark::verify(&proof_bytes, &input.commitment) {
        Ok(valid) => {
            let out = VerifyOutput { valid };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Err(e) => {
            eprintln!("verify error: {e}");
            std::process::exit(1);
        }
    }
}
