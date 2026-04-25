const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy QLSAVerifierV2 (Phase 3+ structural verifier)
  const QLSAVerifierV2 = await hre.ethers.getContractFactory("QLSAVerifierV2");
  const verifier = await QLSAVerifierV2.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifierV2 deployed to:", verifierAddr);

  // 2. Deploy BatchRegistry pointing at QLSAVerifierV2
  const BatchRegistry = await hre.ethers.getContractFactory("BatchRegistry");
  const registry = await BatchRegistry.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistry deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifierV2:", verifierAddr);
  console.log("  BatchRegistry: ", registryAddr);
  console.log("  Owner:         ", deployer.address);
  console.log("\nNOTE: QLSAVerifierV2 is a structural verifier (Phase 3+).");
  console.log("It validates M31 commitment range but does NOT perform full FRI verification.");
  console.log("Replace with the full Circle STARK on-chain verifier before mainnet use.");
  console.log("\nUpgrade path: registry.setVerifier(<full-verifier-address>)");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
