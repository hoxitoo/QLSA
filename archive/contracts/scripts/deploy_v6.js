const hre = require("hardhat");

// QLSA MVP-6 — production deployment: QLSAVerifierVFRI10 + BatchRegistryV6.
//
// VFRI10 is the VFRI9 proof protocol on the Poseidon2 t=4 hash backend
// (wide Merkle + t=4 Fiat-Shamir channel), with the last-layer FRI
// bounded-degree check and full-root Fiat-Shamir absorption.
//
// BatchRegistryV6 verifies each V23 trace group (LOG=10, LOG=8) in its OWN
// transaction (each t=4 verify ≤16.7M gas), finalizing once both groups are
// present and mutually cross-consistent — closing the dual-verify gas wall that
// BatchRegistryV5.submitBatch hits when both t=4 verifies run in one tx.
async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierVFRI10 — production verifier (MVP-6, Poseidon2 t=4).
  const VFRI10 = await hre.ethers.getContractFactory("QLSAVerifierVFRI10");
  const verifier = await VFRI10.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierVFRI10 deployed to:", verifierAddr);

  // 2. Deploy BatchRegistryV6 pointing at QLSAVerifierVFRI10.
  //    Per-group split: submitGroup10 + submitGroup8WithNonces, cross-bound:
  //      boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)
  //      boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)
  const BatchRegistryV6 = await hre.ethers.getContractFactory("BatchRegistryV6");
  const registry = await BatchRegistryV6.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistryV6 deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierVFRI10:", verifierAddr);
  console.log("  BatchRegistryV6:   ", registryAddr);
  console.log("  Owner:             ", deployer.address);
  console.log("\nCommitment scheme (MVP-6 VFRI10):");
  console.log("  log10_commitment = Blake2s(proof10[:32] ‖ boundRoot10)[:16]");
  console.log("  log8_commitment  = Blake2s(proof8[:32]  ‖ boundRoot8)[:16]");
  console.log("  boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)");
  console.log("  boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)");
  console.log("\nFinalization flow (two transactions, ≤16.7M gas each):");
  console.log("  submitGroup10(merkleRoot, traceRoot8,  c10, proof10, hints10)  → ~10.6M gas");
  console.log("  submitGroup8WithNonces(merkleRoot, traceRoot10, c8, proof8, hints8, senders, nonces) → ~7.9M gas");
  console.log("\nNOTE: VFRI10 verifies full FRI + OODS + last-layer + cross-proof binding.");
  console.log("      ML-DSA arithmetic is proved by the off-chain STARK prover (V23).");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
