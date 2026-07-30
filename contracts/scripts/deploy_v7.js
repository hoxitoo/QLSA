const hre = require("hardhat");

// QLSA MVP-7 — production deployment: QLSAVerifierVFRI11 + BatchRegistryV5.
//
// VFRI11 is the VFRI9/VFRI10 proof protocol on the Poseidon2 t=8 hash backend:
// Merkle nodes carry FOUR M31 words (124 bits) instead of t=4's two (62 bits),
// raising node-collision cost from ~2^31 to ~2^62.  Everything else — last-layer
// FRI bounded-degree check, full-root Fiat-Shamir absorption, cross-proof
// binding, the 6-slot hints ABI — is identical to VFRI10.
//
// Why BatchRegistryV5 (single submitBatch) rather than V6's per-group split:
// until the R4.8 Poseidon2 rewrite (2026-07-30) each V23 group verify() cost
// ~8–11M gas, so two verifies in one transaction overran the 16,777,216 (2^24,
// EIP-7825) per-tx cap and the split was mandatory.  Measured after the rewrite,
// a t=8 dual submitBatch costs ~6.06M gas — one transaction, one atomic
// cross-binding check, and a stronger hash than the deployed t=4 stack.
//
// Use deploy_v6.js instead when a lower peak gas per transaction matters more
// than atomicity (V6 splits the same work into ~2.15M + ~1.70M).
async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierVFRI11 — Poseidon2 t=8 backend (4-word/124-bit nodes).
  const VFRI11 = await hre.ethers.getContractFactory("QLSAVerifierVFRI11");
  const verifier = await VFRI11.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierVFRI11 deployed to:", verifierAddr);

  // 2. Deploy BatchRegistryV5 pointing at QLSAVerifierVFRI11.
  //    Atomic dual verify with cross-proof binding computed on-chain:
  //      boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)
  //      boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)
  const BatchRegistryV5 = await hre.ethers.getContractFactory("BatchRegistryV5");
  const registry = await BatchRegistryV5.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistryV5 deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierVFRI11:", verifierAddr);
  console.log("  BatchRegistryV5:   ", registryAddr);
  console.log("  Owner:             ", deployer.address);
  console.log("\nCommitment scheme (MVP-7 VFRI11):");
  console.log("  log10_commitment = Blake2s(proof10[:32] ‖ boundRoot10)[:16]");
  console.log("  log8_commitment  = Blake2s(proof8[:32]  ‖ boundRoot8)[:16]");
  console.log("  boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)");
  console.log("  boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)");
  console.log("\nFinalization flow (ONE transaction):");
  console.log("  submitBatchWithNonces(merkleRoot, c10, proof10, hints10,");
  console.log("                        c8, proof8, hints8, senders, nonces)");
  console.log("  measured: ~6.06M gas total (LOG=10 ~3.34M + LOG=8 ~2.63M + overhead)");
  console.log("\nMerkle node width: 4 M31 words (124-bit) → node collision ~2^62");
  console.log("  (t=4/VFRI10 carries 2 words → ~2^31; 128-bit needs t=16 + recursion)");
  console.log("\nNOTE: VFRI11 verifies full FRI + OODS + last-layer + cross-proof binding.");
  console.log("      ML-DSA arithmetic is proved by the off-chain STARK prover (V23).");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
