const { ethers } = require("hardhat");

async function main() {
  const [signer] = await ethers.getSigners();
  
  const B2 = await ethers.getContractFactory("Blake2sHarness");
  const b2 = await B2.deploy();
  await b2.waitForDeployment();
  
  const B2Y = await ethers.getContractFactory("Blake2sYulHarness");
  const b2y = await B2Y.deploy();
  await b2y.waitForDeployment();
  
  const inputs = [
    { label: "64 bytes", data: "0x" + "aa".repeat(64) },
    { label: "436 bytes (109 cols)", data: "0x" + "ab".repeat(436) },
    { label: "696 bytes", data: "0x" + "cd".repeat(696) },
  ];
  
  for (const {label, data} of inputs) {
    const g1 = await b2.hash.estimateGas(data);
    const g2 = await b2y.hash.estimateGas(data);
    console.log(`${label}: Blake2s=${g1.toString()} Blake2sYul=${g2.toString()} speedup=${(Number(g1)/Number(g2)).toFixed(2)}x`);
  }
}
main().then(() => process.exit(0)).catch(e => { console.error(e.message); process.exit(1); });
