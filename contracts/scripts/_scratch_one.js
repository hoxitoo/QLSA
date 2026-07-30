const hre = require("hardhat");
async function main() {
  const v = await (await hre.ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
  console.log(JSON.stringify({ addr: await v.getAddress() }));
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
