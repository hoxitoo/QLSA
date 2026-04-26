const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierV3 (Phase 3++ structural verifier)
  const QLSAVerifierV3 = await hre.ethers.getContractFactory("QLSAVerifierV3");
  const verifier = await QLSAVerifierV3.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierV3 deployed to:", verifierAddr);

  // 2. Deploy BatchRegistry pointing at QLSAVerifierV3
  const BatchRegistry = await hre.ethers.getContractFactory("BatchRegistry");
  const registry = await BatchRegistry.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistry deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierV3:", verifierAddr);
  console.log("  BatchRegistry: ", registryAddr);
  console.log("  Owner:         ", deployer.address);
  console.log("\nNOTE: QLSAVerifierV3 is a structural verifier (Phase 3++).");
  console.log("It validates M31 commitment range, proof length >= 700 bytes, and trivial-proof guard,");
  console.log("but does NOT perform full FRI decommitment. Replace with the full Circle STARK verifier");
  console.log("before mainnet use.");
  console.log("\nUpgrade path: registry.setVerifier(<full-verifier-address>)");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
