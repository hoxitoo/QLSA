/**
 * Offline compilation helper for environments where binaries.soliditylang.org
 * is not accessible. Uses the locally cached wasm Solc compiler.
 *
 * Usage:  node scripts/compile_offline.js
 *
 * Compiles new contracts to artifacts/ so that `npx hardhat test --no-compile`
 * can run against them.
 */

const fs   = require("fs");
const path = require("path");

const WASM_SOLC = "/root/.cache/hardhat-nodejs/compilers-v2/wasm/soljson-v0.8.26+commit.8a97fa7a.js";
const SRC_DIR   = path.resolve(__dirname, "../src");
const ART_DIR   = path.resolve(__dirname, "../artifacts/src");
const OZ_DIR    = path.resolve(__dirname, "../node_modules/@openzeppelin/contracts");

const wrapper  = require("../node_modules/solc/wrapper");
const compiler = wrapper(require(WASM_SOLC));

// ── Contracts to compile ───────────────────────────────────────────────────
const TARGETS = [
  "IQLSAVerifierV2.sol",
  "QLSAVerifierBound.sol",
  "BatchRegistryV2.sol",
];

function readSrc(rel) {
  return fs.readFileSync(path.join(SRC_DIR, rel), "utf8");
}
function readOZ(rel) {
  return fs.readFileSync(path.join(OZ_DIR, rel), "utf8");
}

// Build flat import map for the compiler's `sources` input.
function buildSources(targets) {
  const src = {};
  for (const t of targets) {
    src[`src/${t}`] = { content: readSrc(t) };
  }

  // OpenZeppelin dependencies
  const ozDeps = [
    "utils/ReentrancyGuard.sol",
    "access/Ownable.sol",
    "utils/Context.sol",
    "utils/StorageSlot.sol",
  ];
  for (const d of ozDeps) {
    try {
      src[`@openzeppelin/contracts/${d}`] = { content: readOZ(d) };
    } catch (_) {}
  }

  // Local interfaces and verifier libs
  const locals = [
    "IQLSAVerifier.sol",
    "verifier/Blake2s.sol",
    "verifier/M31.sol",
  ];
  for (const l of locals) {
    try {
      src[`src/${l}`] = { content: readSrc(l) };
    } catch (_) {}
  }

  return src;
}

function findImport(importPath) {
  // Try @openzeppelin/contracts
  if (importPath.startsWith("@openzeppelin/contracts/")) {
    const rel = importPath.slice("@openzeppelin/contracts/".length);
    try {
      return { contents: readOZ(rel) };
    } catch (e) {
      return { error: `file not found: ${importPath}` };
    }
  }
  // Try ./  or src/ relative
  const candidates = [
    path.join(SRC_DIR, importPath.replace(/^src\//, "")),
    path.join(SRC_DIR, importPath.replace(/^\.\//, "")),
    path.join(__dirname, "..", importPath),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return { contents: fs.readFileSync(c, "utf8") };
    }
  }
  return { error: `file not found: ${importPath}` };
}

function compile(targets) {
  const input = {
    language: "Solidity",
    sources:  buildSources(targets),
    settings: {
      optimizer:    { enabled: true, runs: 200 },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode", "evm.deployedBytecode"] } },
    },
  };

  const output = JSON.parse(
    compiler.compile(JSON.stringify(input), { import: findImport })
  );

  if (output.errors) {
    for (const e of output.errors) {
      if (e.severity === "error") {
        console.error("Compilation error:", e.formattedMessage);
      } else {
        console.warn("Warning:", e.formattedMessage.split("\n")[0]);
      }
    }
    const hasErrors = output.errors.some(e => e.severity === "error");
    if (hasErrors) {
      console.error("Compilation failed.");
      process.exit(1);
    }
  }

  return output.contracts || {};
}

function writeArtifact(srcFile, contractName, contractData) {
  const dir = path.join(ART_DIR, `${srcFile}`, `${contractName}`);
  fs.mkdirSync(dir, { recursive: true });

  const artifact = {
    _format:           "hh-artifact-1",
    contractName,
    sourceName:        `src/${srcFile}`,
    abi:               contractData.abi,
    bytecode:          "0x" + contractData.evm.bytecode.object,
    deployedBytecode:  "0x" + contractData.evm.deployedBytecode.object,
    linkReferences:    {},
    deployedLinkReferences: {},
  };

  const out = path.join(dir, `${contractName}.json`);
  fs.writeFileSync(out, JSON.stringify(artifact, null, 2));
  console.log(`  Wrote ${path.relative(process.cwd(), out)}`);
}

// ── Main ───────────────────────────────────────────────────────────────────
console.log("Compiling with cached wasm Solc", compiler.version(), "...");
const contracts = compile(TARGETS);

for (const [src, names] of Object.entries(contracts)) {
  const srcFile = src.replace(/^src\//, "");
  for (const [name, data] of Object.entries(names)) {
    writeArtifact(srcFile, name, data);
  }
}

console.log("Done.");
