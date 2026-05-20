const { ethers, network } = require("hardhat");
async function main() {
  // Find the actual eth_call gas cap by binary search
  const Factory = await ethers.getContractFactory("Blake2sYulHarness");
  const h = await Factory.deploy(); await h.waitForDeployment();
  const addr = await h.getAddress();
  const iface = h.interface;
  // ~436 byte input = 7 compressions = ~327k gas. Try 50 calls = ~16.4M
  const data50 = iface.encodeFunctionData("hash", ["0x" + "ab".repeat(436)]);
  // wrap in a simple loop - actually just check one call limit
  try {
    const r = await network.provider.request({
      method: "eth_call",
      params: [{to: addr, data: data50, gas: "0x1000000"}, "latest"]
    });
    console.log("16M gas call: ok");
  } catch(e) {
    console.log("16M gas call error:", e.message.slice(0, 200));
  }
  try {
    const r = await network.provider.request({
      method: "eth_call",
      params: [{to: addr, data: data50, gas: "0xFFFFFF"}, "latest"]
    });
    console.log("16.7M gas call: ok");
  } catch(e) {
    console.log("16.7M gas call error:", e.message.slice(0, 200));
  }
}
main().then(() => process.exit(0)).catch(e => { console.error(e.message); process.exit(1); });
