// Measure what a SENDER costs on a live network — the figure the economics
// turn on (ROADMAP § 1.5) — with the same method as test/V7SenderCostProbe.
//
// Why. On Sepolia (2026-11-17/18) the first public run's two first-time
// senders cost 213,285 gas against 62,008 locally (~3.4x), while the same
// batch WITHOUT senders cost only +2.96%. That points at storage writes being
// priced differently there — an inference from two numbers. This measures it.
//
// Method — every figure is gasUsed of a SENT transaction, MARGINAL, so the
// ~15M of shared batch cost and the 21,000 base cancel:
//   real BatchRegistryV7, a FRESH registry per call (a fresh registry is what
//   makes each sender first-time, and lets the fixture's batch be finalized
//   again): the fixture batch with 0, 1, 5, 10 distinct senders.
//     10, not 25 as locally: if a sender really costs ~100k here, 25 would
//     exceed the 16,777,216 per-transaction cap.
//   NonceLoopHarness (V7's nonce loop verbatim, no proofs — cheap): first-time
//   senders at 5/10/25 (5->10 cross-checks the harness against the real
//   contract on THIS network), and RETURNING senders at 10/25 (two calls into
//   one harness; the second is measured) — the steady-state cost the real
//   contract cannot produce.
//
// The sequence is fixed, so running it locally and on Sepolia gives figures
// that compare line by line.
//
// Usage:
//   [VERIFIER_ADDRESS=0x…]  QLSAVerifierRecursive to reuse (deployed if unset)
//   [RESULTS_PATH=out.json] where to write the raw figures
//   npx hardhat run scripts/probe_sender_cost.js --network sepolia
"use strict";

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { gasPrice, bundleTuple } = require("./_testnet");

const FIXTURE = path.join(__dirname, "..", "test", "fixtures", "tree_recursive_bundles_e2e.json");
const CAP = 16_777_216n;
const GAS_LIMIT = 16_777_000n;
// Calldata a signature carries and an aggregated batch no longer needs on
// chain: 3,309 B at 16 gas per byte (ROADMAP § 1.5). The 16 is mainnet's
// pricing; on a network that prices calldata differently this is approximate.
const SAVED_PER_SIG = 52_944n;

async function main() {
  const { ethers } = hre;
  const fx = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
  const b10 = bundleTuple(fx.bundle10);
  const b8 = bundleTuple(fx.bundle8);
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
    console.log(`  ${label.padEnd(34)} ${rc.gasUsed.toString().padStart(10)}  ${tx.hash}`);
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
  const Harness = await ethers.getContractFactory("NonceLoopHarness");
  const senders = (n) => Array.from({ length: n }, (_, i) => ethers.zeroPadValue(ethers.toBeHex(i + 1), 32));
  const ones = (n, v) => Array.from({ length: n }, () => v);

  async function freshRegistry(tag) {
    const reg = await RegistryV7.deploy(owner.address, verifier, ethers.ZeroHash, 0, ov);
    await sent(`deploy registry (${tag})`, Promise.resolve(reg.deploymentTransaction()));
    return reg;
  }

  console.log("\nreal BatchRegistryV7, fixture batch, fresh registry each:");
  const real = {};
  {
    const reg = await freshRegistry("0 senders");
    real[0] = (await sent("submitBatch, 0 senders",
      reg.submitBatch(fx.merkleRoot, fx.txListRoot, b10, b8, { ...ov, gasLimit: GAS_LIMIT }))).gasUsed;
  }
  for (const n of [1, 5, 10]) {
    const reg = await freshRegistry(`${n} senders`);
    real[n] = (await sent(`submitBatchWithNonces, ${n} new`,
      reg.submitBatchWithNonces(fx.merkleRoot, fx.txListRoot, b10, b8, senders(n), ones(n, 1n),
        { ...ov, gasLimit: GAS_LIMIT }))).gasUsed;
  }

  console.log("\nNonceLoopHarness (V7's nonce loop, no proofs), fresh harness each:");
  const hCold = {};
  for (const n of [5, 10, 25]) {
    const h = await Harness.deploy(ov);
    await h.waitForDeployment();
    hCold[n] = (await sent(`harness, ${n} new senders`, h.applyNonces(senders(n), ones(n, 1n), ov))).gasUsed;
  }
  const hRet = {};
  for (const n of [10, 25]) {
    const h = await Harness.deploy(ov);
    await h.waitForDeployment();
    await sent(`harness, ${n} senders (warm-up)`, h.applyNonces(senders(n), ones(n, 1n), ov));
    hRet[n] = (await sent(`harness, ${n} RETURNING senders`, h.applyNonces(senders(n), ones(n, 2n), ov))).gasUsed;
  }

  // ── derived figures ──────────────────────────────────────────────────────
  const d = {
    batchNoSenders: real[0],
    firstSenderIncludingWithNoncesOverhead: real[1] - real[0],
    realColdMarginal_1to5: (real[5] - real[1]) / 4n,
    realColdMarginal_5to10: (real[10] - real[5]) / 5n,
    harnessColdMarginal_5to10: (hCold[10] - hCold[5]) / 5n,
    harnessColdMarginal_10to25: (hCold[25] - hCold[10]) / 15n,
    harnessReturningMarginal_10to25: (hRet[25] - hRet[10]) / 15n,
  };
  d.storageDelta_coldMinusReturning = d.harnessColdMarginal_10to25 - d.harnessReturningMarginal_10to25;
  const harnessDeviation = Number(
    ((d.harnessColdMarginal_5to10 - d.realColdMarginal_5to10) * 10000n) / d.realColdMarginal_5to10) / 100;
  const headroom = CAP - real[1];
  const ceilCold = headroom / d.harnessColdMarginal_10to25;
  const ceilRet = headroom / d.harnessReturningMarginal_10to25;
  const be = (m) => (m < SAVED_PER_SIG ? real[1] / (SAVED_PER_SIG - m) : null);

  console.log("\nderived (marginal, per sender):");
  for (const [k, v] of Object.entries(d)) console.log(`  ${k.padEnd(40)} ${v.toString().padStart(10)}`);
  console.log(`  harness vs real cold, 5->10           ${harnessDeviation.toFixed(2)}%  (the harness may be used if within 5%)`);
  console.log(`  headroom above a 1-sender batch       ${headroom}`);
  console.log(`  sender ceiling, first-time senders    ~${ceilCold}`);
  console.log(`  sender ceiling, returning senders     ~${ceilRet}`);
  const beCold = be(d.harnessColdMarginal_10to25), beRet = be(d.harnessReturningMarginal_10to25);
  console.log(`  break-even N (first-time)             ${beCold === null ? "UNREACHABLE" : "~" + beCold}`);
  console.log(`  break-even N (returning)              ${beRet === null ? "UNREACHABLE" : "~" + beRet}`);
  console.log(`  (break-even assumes ${SAVED_PER_SIG} gas of calldata saved per signature — mainnet pricing)`);

  const out = {
    network: hre.network.name, chainId: chainId.toString(), sender: owner.address, verifier,
    gasPriceWei: price.toString(), date: new Date().toISOString().slice(0, 10),
    real: Object.fromEntries(Object.entries(real).map(([k, v]) => [k, v.toString()])),
    harnessCold: Object.fromEntries(Object.entries(hCold).map(([k, v]) => [k, v.toString()])),
    harnessReturning: Object.fromEntries(Object.entries(hRet).map(([k, v]) => [k, v.toString()])),
    derived: Object.fromEntries(Object.entries(d).map(([k, v]) => [k, v.toString()])),
    harnessDeviationPct: harnessDeviation,
    headroom: headroom.toString(), ceilingFirstTime: ceilCold.toString(), ceilingReturning: ceilRet.toString(),
    breakEvenFirstTime: beCold === null ? null : beCold.toString(),
    breakEvenReturning: beRet === null ? null : beRet.toString(),
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
