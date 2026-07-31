const hre = require("hardhat");

// QLSA MVP-8 — recursive stack: QLSAVerifierVFRI11 + QLSAVerifierRecursive +
// BatchRegistryV7.
//
// What makes this stack different from v7 (direct VFRI11 + BatchRegistryV5):
// the registry does not verify the V23 groups' proofs itself. It verifies, per
// group, a STARK attesting that the inner VFRI11 proof was verified, plus the
// cheap on-chain half the recursion deliberately leaves outside the circuit
// (Fiat-Shamir channel replay + last-layer bounded-degree check).
//
// Why it exists: at the production 20 FRI queries — 130-bit on-chain soundness,
// log_blowup(6)*20 + pow_bits(10) — DIRECT verification of a V23 group no longer
// fits an Ethereum transaction at all, while the recursive route finalizes the
// whole batch in one (measured: 13,128,561 gas; see docs/conclusions.md).
//
// Below roughly 2 queries the direct v7 stack is CHEAPER. This stack is a
// soundness mechanism, not a gas optimisation — deploy it when you want 130-bit,
// not to save gas on a demo config.
async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. The OUTER proof verifier — a plain VFRI11, used on the recursive trace.
  const VFRI11 = await hre.ethers.getContractFactory("QLSAVerifierVFRI11");
  const vfri11 = await VFRI11.deploy();
  await vfri11.waitForDeployment();
  const vfri11Addr = await vfri11.getAddress();
  console.log("QLSAVerifierVFRI11 deployed to:", vfri11Addr);

  // 2. The recursive entry point: channel replay + last-layer check + outer proof.
  const Recursive = await hre.ethers.getContractFactory("QLSAVerifierRecursive");
  const recursive = await Recursive.deploy(vfri11Addr);
  await recursive.waitForDeployment();
  const recursiveAddr = await recursive.getAddress();
  console.log("QLSAVerifierRecursive deployed to:", recursiveAddr);

  // 3. The registry that finalizes a batch from two cross-bound recursive bundles.
  const RegistryV7 = await hre.ethers.getContractFactory("BatchRegistryV7");
  const registry = await RegistryV7.deploy(deployer.address, recursiveAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistryV7 deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierVFRI11:     ", vfri11Addr);
  console.log("  QLSAVerifierRecursive:  ", recursiveAddr);
  console.log("  BatchRegistryV7:        ", registryAddr);
  console.log("  Owner:                  ", deployer.address);

  console.log("\nCross-proof binding (computed on-chain, checked at submit):");
  console.log("  bundle10.inner.batchRoot == keccak256(merkleRoot | traceRoot8)");
  console.log("  bundle8.inner.batchRoot  == keccak256(merkleRoot | traceRoot10)");

  console.log("\nFinalization: ONE transaction");
  console.log("  submitBatchWithNonces(merkleRoot, bundle10, bundle8, senders, nonces)");
  console.log("  measured at n_queries=20 (130-bit): ~13.13M gas");

  console.log("\nNOTE: the recursion proves the inner VFRI11 verification; the");
  console.log("      ML-DSA arithmetic itself is proved by the off-chain V23 prover.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
