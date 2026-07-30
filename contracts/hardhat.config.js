require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: "../.env" });

// Optional escape hatch for sandboxes whose egress policy blocks
// binaries.soliditylang.org (hardhat's compiler download host).  With
// QLSA_LOCAL_SOLCJS=1 the compile task uses the `solc` npm package's
// soljson.js instead of a downloaded native binary — same compiler version,
// just slower.  Inert without the env var, so CI is unaffected.
//
//   npm install --no-save solc@0.8.35
//   QLSA_LOCAL_SOLCJS=1 npx hardhat test
if (process.env.QLSA_LOCAL_SOLCJS === "1") {
  const { subtask } = require("hardhat/config");
  const {
    TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD,
  } = require("hardhat/builtin-tasks/task-names");

  subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, _hre, runSuper) => {
    try {
      const local = require("solc/package.json").version;
      if (local.split("+")[0] !== args.solcVersion) return runSuper();
      return {
        compilerPath: require.resolve("solc/soljson.js"),
        isSolcJs: true,
        version: args.solcVersion,
        longVersion: local,
      };
    } catch {
      return runSuper();
    }
  });
}

const RPC_URL         = process.env.RPC_URL         || "";
const POLYGON_ZKEVM   = process.env.POLYGON_ZKEVM_RPC || "";
const PRIVATE_KEY     = process.env.PRIVATE_KEY      || "";

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  paths: {
    sources:   "./src",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },

  solidity: {
    version: "0.8.35",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
    },
  },

  networks: {
    // Allow large calldata for MAX_PROOF_LENGTH guard tests (1 MiB proof)
    hardhat: {
      blockGasLimit: 100_000_000,
      allowUnlimitedContractSize: true,
    },

    // Polygon zkEVM testnet
    cardona: {
      url:      RPC_URL,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
      chainId:  2442,
    },

    // Ethereum Sepolia testnet
    sepolia: {
      url:      "https://ethereum-sepolia-rpc.publicnode.com",
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
      chainId:  11155111,
    },

    // Polygon zkEVM mainnet
    polygonZkEvm: {
      url:      POLYGON_ZKEVM,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
      chainId:  1101,
    },
  },

  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },

  mocha: {
    timeout: 60_000,
  },
};
