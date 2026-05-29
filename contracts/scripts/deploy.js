const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierVFRI7 — production verifier (MVP-5)
  //    Full K-round FRI + OODS quotient check + Fiat-Shamir query derivation
  //    + cross-proof binding (mixRoot(merkleRoot) before drawQueries).
  const VFRI7 = await hre.ethers.getContractFactory("QLSAVerifierVFRI7");
  const verifier = await VFRI7.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierVFRI7 deployed to:", verifierAddr);

  // 2. Deploy BatchRegistryV4 pointing at QLSAVerifierVFRI7
  //    Requires dual VFRI7 proofs (LOG=10 + LOG=8) with cross-bound roots:
  //      boundRoot10 = keccak256(batchRoot ‖ traceRoot8)
  //      boundRoot8  = keccak256(batchRoot ‖ traceRoot10)
  const BatchRegistryV4 = await hre.ethers.getContractFactory("BatchRegistryV4");
  const registry = await BatchRegistryV4.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistryV4 deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierVFRI7:", verifierAddr);
  console.log("  BatchRegistryV4:  ", registryAddr);
  console.log("  Owner:            ", deployer.address);
  console.log("\nCommitment scheme (MVP-5 VFRI7):");
  console.log("  log10_commitment = Blake2s(proof10[:32] ‖ boundRoot10)[:16]");
  console.log("  log8_commitment  = Blake2s(proof8[:32]  ‖ boundRoot8)[:16]");
  console.log("  boundRoot10 = keccak256(batchRoot ‖ traceRoot8)");
  console.log("  boundRoot8  = keccak256(batchRoot ‖ traceRoot10)");
  console.log("\nOn-chain FRI security: 6 × n_queries + 10 bits");
  console.log("  Default n=1 → 16 bits (testnet/demo). Set N_FRI_QUERIES env var to increase.");
  console.log("\nNOTE: VFRI7 verifies full FRI protocol + OODS + cross-proof binding.");
  console.log("      ML-DSA arithmetic is proved by the off-chain STARK prover (V23).");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
