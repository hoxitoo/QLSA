const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);

  // 1. Deploy stub verifier
  const QLSAVerifier = await hre.ethers.getContractFactory("QLSAVerifier");
  const verifier = await QLSAVerifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("QLSAVerifier (stub) deployed to:", verifierAddr);

  // 2. Deploy BatchRegistry
  const BatchRegistry = await hre.ethers.getContractFactory("BatchRegistry");
  const registry = await BatchRegistry.deploy(deployer.address, verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("BatchRegistry deployed to:", registryAddr);

  console.log("\nDeployment summary:");
  console.log("  QLSAVerifier:", verifierAddr);
  console.log("  BatchRegistry:", registryAddr);
  console.log("\nNOTE: QLSAVerifier is a prototype stub.");
  console.log("Replace with Stwo on-chain verifier before mainnet use.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
