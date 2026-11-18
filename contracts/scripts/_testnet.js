// Shared by the testnet scripts (deploy_v8.js, replay_tree_fixture.js) and the
// tests, so each rule has ONE implementation.
"use strict";

const hre = require("hardhat");

// The gas price every testnet transaction uses: the node's eth_gasPrice, raised
// to $QLSA_MIN_GAS_PRICE_WEI when that is set and higher — the same rule as
// testnet/submit.py's gas_price_for, so the workflows' balance checks price a
// run exactly as it is sent.
//
// Without an explicit price Hardhat's signer chooses its own EIP-1559 fees. On
// 2026-10-11 Sepolia's suggested price was ~15 wei, the signer still asked the
// node for ~7 gwei per gas up front, and an account the check had passed was
// refused: "insufficient funds … want 34489759103469277".
async function gasPrice() {
  const suggested = BigInt(await hre.network.provider.send("eth_gasPrice", []));
  const raw = (process.env.QLSA_MIN_GAS_PRICE_WEI || "").trim();
  if (!raw) return suggested;
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error(`QLSA_MIN_GAS_PRICE_WEI must be an integer number of wei, got ${raw}`);
  }
  const floor = BigInt(raw);
  return suggested > floor ? suggested : floor;
}

// A recursive bundle from a Rust-written fixture, as BatchRegistryV7 takes it.
function bundleTuple(b) {
  return {
    inner: {
      traceRoot: b.inner.traceRoot,
      oodsComboPos: b.inner.oodsComboPos,
      oodsComboNeg: b.inner.oodsComboNeg,
      compRoot: b.inner.compRoot,
      friLayerRoots: b.inner.friLayerRoots,
      batchRoot: b.inner.batchRoot,
      treeDepth: b.inner.treeDepth,
      nQueries: b.inner.nQueries,
    },
    outerProof: b.outerProof,
    outerCommitment: b.outerCommitment,
    outerHints: b.outerHints,
    lastLayerEvals: b.lastLayerEvals,
  };
}

module.exports = { gasPrice, bundleTuple };
