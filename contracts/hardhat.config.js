require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: "../.env" });

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
    version: "0.8.26",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: false,
    },
  },

  networks: {
    // Allow large calldata for MAX_PROOF_LENGTH guard tests (1 MiB proof)
    hardhat: {
      blockGasLimit: 100_000_000,
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
