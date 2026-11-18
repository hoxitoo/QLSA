// Replay the reference tree batch on a live network and compare its gas with
// the local measurement.
//
// Why. The first public run (Sepolia, 2026-11-17) used 15,312,023 gas, 4.0%
// above the same command on a standalone hardhat node. That run's proof was
// fresh — new keys, new trace — so the gap could be the chain's gas pricing or
// something about that proof. This script removes the second possibility: it
// sends the FIXTURE's batch (contracts/test/fixtures/tree_recursive_bundles_e2e.json),
// byte-for-byte the calldata whose gas the test suite re-measures as
// `v7_tree_submitBatch` in measurements.json. Same calldata, same contract code:
// any difference is the network's.
//
// Usage:
//   REGISTRY_ADDRESS=0x… npx hardhat run scripts/replay_tree_fixture.js --network sepolia
// Optional QLSA_MIN_GAS_PRICE_WEI — the floor, as for every testnet transaction.
//
// A fixture batch can be finalized once per registry: a second run reports the
// earlier finalization instead of sending.
"use strict";

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { gasPrice, bundleTuple } = require("./_testnet");

const FIXTURE = path.join(__dirname, "..", "test", "fixtures", "tree_recursive_bundles_e2e.json");
const MEASUREMENTS = path.join(__dirname, "..", "test", "fixtures", "measurements.json");
// What testnet/submit.py uses too; the call needs ~14.7M.
const GAS_LIMIT = 16_700_000n;

async function main() {
  const addr = (process.env.REGISTRY_ADDRESS || "").trim();
  if (!hre.ethers.isAddress(addr)) {
    throw new Error(`REGISTRY_ADDRESS must be the deployed BatchRegistryV7, got "${addr}"`);
  }
  const fx = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
  const reference = BigInt(
    JSON.parse(fs.readFileSync(MEASUREMENTS, "utf8")).entries.v7_tree_submitBatch.value);

  const [sender] = await hre.ethers.getSigners();
  const registry = await hre.ethers.getContractAt("BatchRegistryV7", addr);
  const { chainId } = await hre.ethers.provider.getNetwork();
  console.log("network  :", hre.network.name, "chainId", chainId.toString());
  console.log("registry :", addr);
  console.log("sender   :", sender.address);
  console.log("batch    :", fx.merkleRoot, `(${fx.leafCount} signatures, fixture)`);

  if (await registry.isBatchFinalized(fx.merkleRoot)) {
    console.log("RESULT   : already finalized on this registry — the fixture was replayed before;");
    console.log("           its gasUsed is in that transaction's receipt. Nothing sent.");
    return;
  }

  const price = await gasPrice();
  console.log("gasPrice :", hre.ethers.formatUnits(price, "gwei"), "gwei (legacy)");
  const tx = await registry.submitBatch(
    fx.merkleRoot, fx.txListRoot, bundleTuple(fx.bundle10), bundleTuple(fx.bundle8),
    { gasLimit: GAS_LIMIT, gasPrice: price });
  console.log("tx_hash  :", tx.hash);
  const rc = await tx.wait();
  if (rc.status !== 1) throw new Error(`transaction reverted (status ${rc.status})`);
  if (!(await registry.isBatchFinalized(fx.merkleRoot))) {
    throw new Error("mined but the batch is not finalized");
  }

  const diff = rc.gasUsed - reference;
  const pct = Number((diff * 100000n) / reference) / 1000;
  console.log("gasUsed  :", rc.gasUsed.toString());
  console.log("reference:", reference.toString(), "(local, measurements.json v7_tree_submitBatch)");
  console.log(`diff     : ${diff >= 0n ? "+" : ""}${diff} (${pct >= 0 ? "+" : ""}${pct.toFixed(3)}%)`);
  console.log(
    Math.abs(pct) < 0.1
      ? "VERDICT  : same as local — the 2026-11-17 gap came from that run's proof, not the network"
      : "VERDICT  : the network prices the SAME calldata differently — the gap is the chain's gas schedule"
  );
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
