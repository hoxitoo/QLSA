// M31.P = 2^31 − 1
const P = 2_147_483_647n;

// Encode an M31 field element as the first 4 LE bytes of a bytes8 commitment,
// with trailing 4 bytes zero (as the Stwo prover produces).
function makeCommitment(m31Val) {
  const v = BigInt(m31Val);
  const b0 = (v >>  0n) & 0xFFn;
  const b1 = (v >>  8n) & 0xFFn;
  const b2 = (v >> 16n) & 0xFFn;
  const b3 = (v >> 24n) & 0xFFn;
  return (b0 << 56n) | (b1 << 48n) | (b2 << 40n) | (b3 << 32n);
}

function toBytes8Hex(bigint) {
  return "0x" + bigint.toString(16).padStart(16, "0");
}

module.exports = { P, makeCommitment, toBytes8Hex };
