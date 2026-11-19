// Measure the FOLDED nonce path (Ф3.2) on a live network: a batch that also
// moves the nonce accumulator, in one transaction —
// BatchRegistryV7.submitBatchWithNonceUpdates — and, beside it, the plain batch
// on the one-slot record.
//
// Why. Locally a nonce update inside the batch proof costs 2,119 gas (1 -> 25)
// and 3,335 (25 -> 150, across a root-depth step), against the mapping's
// 12,085 / 28,777 per sender. On Sepolia the mapping is dearer still — a NEW
// storage slot costs +80,820 there (sender_cost_sepolia.json) — and the folded
// path writes no new slot per sender. Whether the network leaves the folded
// marginal where it is locally is what this measures. The plain batch shows
// what the one-slot record (5 new slots -> 1) is worth there.
//
// Sends 8 transactions: 4 fresh registries (reusing the deployed verifier) —
// one mapping-mode for the plain batch, three accumulator-mode at depth 16 for
// 1 / 25 / 150 updates, each from the empty tree — and the 4 batches.
//
// Every check reads the transaction's OWN receipt (its events), never a fresh
// eth_call: a public RPC is a load balancer, and on 2026-11-19 the receipt came
// from one backend while the follow-up `nonceStateRoot()` read hit another a
// block behind and returned the old root — a mined, correct transaction
// reported as a failure.
//
// Usage:
//   [STATEMENTS=plain,1,25,150] which parts to run (default all); a rerun of a
//                           part that failed need not pay for the others again
//   [VERIFIER_ADDRESS=0x…]  QLSAVerifierRecursive to reuse (deployed if unset)
//   [RESULTS_PATH=out.json] where to write the raw figures
//   npx hardhat run scripts/probe_folded_nonce.js --network sepolia
"use strict";

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { gasPrice, bundleTuple } = require("./_testnet");

const FIX = path.join(__dirname, "..", "test", "fixtures");
const FOLD = JSON.parse(fs.readFileSync(path.join(FIX, "tree_nonce_bundles_e2e.json"), "utf8"));
const TREE = JSON.parse(fs.readFileSync(path.join(FIX, "tree_recursive_bundles_e2e.json"), "utf8"));
const M = JSON.parse(fs.readFileSync(path.join(FIX, "measurements.json"), "utf8")).entries;
const CAP = 16_777_216n;
const GAS_LIMIT = 16_777_000n;
// Calldata a signature carries and an aggregated batch no longer needs on
// chain: 3,309 B at 16 gas per byte (ROADMAP § 1.5) — mainnet's pricing.
const SAVED_PER_SIG = 52_944n;

const updates = (st) => st.updates.map((u) => ({
  index: u.index, oldNonce: BigInt(u.oldNonce), newNonce: BigInt(u.newNonce), postRoot: u.postRoot,
}));

async function main() {
  const { ethers } = hre;
  const [owner] = await ethers.getSigners();
  const { chainId } = await ethers.provider.getNetwork();
  const price = await gasPrice();
  const ov = { gasPrice: price };
  const txs = [];
  const sent = async (label, txPromise) => {
    const tx = await txPromise;
    const rc = await tx.wait();
    if (rc.status !== 1) throw new Error(`${label}: reverted`);
    txs.push({ label, hash: tx.hash, gasUsed: rc.gasUsed.toString() });
    console.log(`  ${label.padEnd(36)} ${rc.gasUsed.toString().padStart(10)}  ${tx.hash}`);
    return rc;
  };

  console.log("network :", hre.network.name, "chainId", chainId.toString());
  console.log("sender  :", owner.address);
  console.log("gasPrice:", ethers.formatUnits(price, "gwei"), "gwei (legacy)");

  let verifier = (process.env.VERIFIER_ADDRESS || "").trim();
  if (!verifier) {
    const v11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy(ov);
    await v11.waitForDeployment();
    const rec = await (await ethers.getContractFactory("QLSAVerifierRecursive"))
      .deploy(await v11.getAddress(), ov);
    await rec.waitForDeployment();
    verifier = await rec.getAddress();
    console.log("verifier: deployed", verifier);
  } else {
    if ((await ethers.provider.getCode(verifier)) === "0x") throw new Error("no code at VERIFIER_ADDRESS");
    console.log("verifier: reusing", verifier);
  }

  const RegistryV7 = await ethers.getContractFactory("BatchRegistryV7");
  const deploy = async (tag, root, depth) => {
    const reg = await RegistryV7.deploy(owner.address, verifier, root, depth, ov);
    const rc = await sent(`deploy registry (${tag})`, Promise.resolve(reg.deploymentTransaction()));
    return [reg, rc.gasUsed];
  };

  const ALL = ["plain", "1", "25", "150"];
  const want = (process.env.STATEMENTS || ALL.join(",")).split(",").map((x) => x.trim()).filter(Boolean);
  for (const w of want) if (!ALL.includes(w)) throw new Error(`STATEMENTS: unknown part "${w}"`);
  console.log("parts   :", want.join(", "));

  // The checks, from the receipt alone (see the header).
  const events = (reg, rc, name) => rc.logs
    .filter((l) => l.address.toLowerCase() === reg.target.toLowerCase())
    .map((l) => { try { return reg.interface.parseLog(l); } catch { return null; } })
    .filter((e) => e && e.name === name);
  const expectFinalized = (reg, rc, label) => {
    if (!events(reg, rc, "BatchFinalized").some((e) => e.args.merkleRoot === FOLD.merkleRoot)) {
      throw new Error(`${label}: no BatchFinalized for the batch in the receipt`);
    }
  };

  let plain = null, deployGas = null;
  if (want.includes("plain")) {
    console.log("\nplain batch, one-slot record:");
    const [plainReg, dg] = await deploy("mapping", ethers.ZeroHash, 0);
    deployGas = dg;
    const rc = await sent("submitBatch (plain)", plainReg.submitBatch(
      TREE.merkleRoot, TREE.txListRoot, bundleTuple(TREE.bundle10), bundleTuple(TREE.bundle8),
      { ...ov, gasLimit: GAS_LIMIT }));
    expectFinalized(plainReg, rc, "plain");
    plain = rc.gasUsed;
  }

  const g = {};
  const folded = ["1", "25", "150"].filter((n) => want.includes(n));
  if (folded.length) {
    console.log("\nfolded batch, depth", FOLD.depth, "— fresh registry each, from the empty tree:");
  }
  for (const n of folded) {
    const st = FOLD.statements[n];
    const [reg] = await deploy(`accumulator, ${n}`, FOLD.emptyRoot, FOLD.depth);
    const rc = await sent(`submitBatchWithNonceUpdates, ${n}`, reg.submitBatchWithNonceUpdates(
      FOLD.merkleRoot, FOLD.txListRoot, bundleTuple(st.bundle10), bundleTuple(st.bundle8),
      st.senders, updates(st), st.newRoot, { ...ov, gasLimit: GAS_LIMIT }));
    expectFinalized(reg, rc, n);
    const moved = events(reg, rc, "NonceStateAdvanced");
    if (moved.length !== 1 || moved[0].args.newRoot !== st.newRoot
        || moved[0].args.oldRoot !== FOLD.emptyRoot || moved[0].args.updates !== BigInt(n)) {
      throw new Error(`${n}: the receipt does not move the nonce root to the statement's`);
    }
    g[n] = rc.gasUsed;
  }

  const local = (k) => BigInt(M[k].value);
  const vs = (x, k) => `${x}  (local ${local(k)}, ${x >= local(k) ? "+" : ""}${x - local(k)})`;
  const has = (...ks) => ks.every((k) => g[k] !== undefined);
  const d = {};
  console.log("\nderived (each line needs its parts; a partial run prints what it has):");
  if (plain !== null) console.log(`  plain batch                     ${vs(plain, "v7_tree_submitBatch")}`);
  if (has("1")) console.log(`  folded, 1 update                ${vs(g["1"], "v7_folded_nonce_1update")}`);
  if (plain !== null && has("1")) console.log(`  folding overhead at 1 update    ${g["1"] - plain}`);
  if (has("1", "25")) {
    d.m1_25 = (g["25"] - g["1"]) / 24n;
    console.log(`  marginal per update, 1->25      ${vs(d.m1_25, "v7_folded_nonce_marginal")}`);
  }
  if (has("25", "150")) {
    d.m25_150 = (g["150"] - g["25"]) / 125n;
    console.log(`  marginal per update, 25->150    ${vs(d.m25_150, "v7_folded_nonce_marginal_150")}`);
  }
  if (has("150")) console.log(`  folded, 150 updates             ${g["150"]}  (local 15063104, ${g["150"] >= 15063104n ? "+" : ""}${g["150"] - 15063104n})`);
  if (has("1") && d.m25_150 !== undefined) {
    d.headroom = CAP - g["1"];
    d.ceiling = d.headroom / d.m25_150;
    d.breakEven = d.m25_150 < SAVED_PER_SIG ? g["1"] / (SAVED_PER_SIG - d.m25_150) : null;
    console.log(`  headroom above 1 update         ${d.headroom}`);
    console.log(`  update ceiling (at 25->150)     ~${d.ceiling}  (the root grows a level past ~150-300)`);
    console.log(`  break-even N                    ${d.breakEven === null ? "UNREACHABLE" : "~" + d.breakEven}`);
    console.log(`  (break-even assumes ${SAVED_PER_SIG} gas of calldata saved per signature — mainnet pricing)`);
  }
  if (deployGas !== null) console.log(`  registry deploy                 ${deployGas}  (cap ${CAP})`);

  const str = (v) => (v === null || v === undefined ? null : v.toString());
  const out = {
    network: hre.network.name, chainId: chainId.toString(), sender: owner.address, verifier,
    gasPriceWei: price.toString(), date: new Date().toISOString().slice(0, 10), parts: want,
    depth: FOLD.depth, registryDeploy: str(deployGas), plainBatch: str(plain),
    folded: Object.fromEntries(Object.entries(g).map(([k, v]) => [k, v.toString()])),
    derived: Object.fromEntries(Object.entries(d).map(([k, v]) => [k, str(v)])),
    transactions: txs,
  };
  if (process.env.RESULTS_PATH) {
    fs.writeFileSync(process.env.RESULTS_PATH, JSON.stringify(out, null, 2) + "\n");
    console.log("\nresults written to", process.env.RESULTS_PATH);
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
