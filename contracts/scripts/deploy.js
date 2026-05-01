const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierBound (Phase 6 — Merkle-root-bound verifier)
  //    Commitment = Blake2s(proof[0:32] ∥ merkleRoot)[0:8]
  const QLSAVerifierBound = await hre.ethers.getContractFactory("QLSAVerifierBound");
  const verifier = await QLSAVerifierBound.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierBound deployed to:", verifierAddr);

  // 2. Deploy BatchRegistryV2 pointing at QLSAVerifierBound
  const BatchRegistryV2 = await hre.ethers.getContractFactory("BatchRegistryV2");
  const registry = await BatchRegistryV2.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistryV2 deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierBound:", verifierAddr);
  console.log("  BatchRegistryV2:  ", registryAddr);
  console.log("  Owner:            ", deployer.address);
  console.log("\nCommitment scheme (Phase 6):");
  console.log("  onchain_commitment = Blake2s(proof[0:32] || merkleRoot)[0:8]");
  console.log("  Python: hashlib.blake2s(proof[:32] + merkle_root[:32]).digest()[:8].hex()");
  console.log("\nUpgrade path: registry.setVerifier(<full-circle-stark-verifier>)");
  console.log("\nNOTE: QLSAVerifierBound cryptographically binds proof to Merkle root but");
  console.log("does NOT perform full FRI decommitment or ML-DSA signature verification.");
  console.log("Replace with the full Circle STARK verifier before mainnet use.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
