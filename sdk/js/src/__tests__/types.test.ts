import { describe, expect, it } from "@jest/globals";
import type {
  BatchStatus,
  NodeStats,
  SubmitResult,
  TransactionPayload,
  WitnessStatus,
} from "../types.js";

describe("TransactionPayload", () => {
  it("accepts a valid payload object", () => {
    const tx: TransactionPayload = {
      sender: "a".repeat(64),
      recipient: "b".repeat(64),
      amount: 100,
      nonce: 0,
      publicKey: "deadbeef",
      signature: "cafebabe",
    };
    expect(tx.amount).toBe(100);
    expect(tx.sender.length).toBe(64);
  });
});

describe("SubmitResult", () => {
  it("accepted result has no error", () => {
    const r: SubmitResult = { accepted: true, mempoolSize: 1 };
    expect(r.error).toBeUndefined();
  });

  it("rejected result carries error string", () => {
    const r: SubmitResult = { accepted: false, mempoolSize: 0, error: "invalid signature" };
    expect(r.accepted).toBe(false);
    expect(r.error).toBe("invalid signature");
  });
});

describe("BatchStatus", () => {
  it("proven batch has all fields", () => {
    const s: BatchStatus = {
      batchId: "abc123",
      txCount: 8,
      merkleRoot: "f".repeat(128),
      isProven: true,
      starkCommitment: "0".repeat(32),
      hasWitness: true,
      witnessCommitment: "1".repeat(32),
      hasVfri7: false,
    };
    expect(s.isProven).toBe(true);
    expect(s.hasWitness).toBe(true);
    expect(s.witnessCommitment).toHaveLength(32);
    expect(s.hasVfri7).toBe(false);
  });

  it("unproven batch has optional fields undefined", () => {
    const s: BatchStatus = {
      batchId: "xyz",
      txCount: 2,
      merkleRoot: "a".repeat(128),
      isProven: false,
      hasWitness: false,
      hasVfri7: false,
    };
    expect(s.starkCommitment).toBeUndefined();
    expect(s.witnessCommitment).toBeUndefined();
    expect(s.vfri7CommitmentLog10).toBeUndefined();
    expect(s.vfri7CommitmentLog8).toBeUndefined();
  });

  it("vfri7 batch carries dual commitment fields", () => {
    const s: BatchStatus = {
      batchId: "vfri7-test",
      txCount: 1,
      merkleRoot: "c".repeat(128),
      isProven: false,
      hasWitness: true,
      witnessCommitment: "a".repeat(32),
      hasVfri7: true,
      vfri7CommitmentLog10: "d".repeat(32),
      vfri7CommitmentLog8: "e".repeat(32),
    };
    expect(s.hasVfri7).toBe(true);
    expect(s.vfri7CommitmentLog10).toHaveLength(32);
    expect(s.vfri7CommitmentLog8).toHaveLength(32);
  });
});

describe("WitnessStatus", () => {
  it("no-witness status has empty maxNorms, no vfri7, zero security fields", () => {
    const ws: WitnessStatus = {
      hasWitness: false, maxNorms: [], hasVfri7: false, nFriQueries: 0, friSecurityBits: 0,
    };
    expect(ws.hasWitness).toBe(false);
    expect(ws.maxNorms).toHaveLength(0);
    expect(ws.onchainCommitment).toBeUndefined();
    expect(ws.cTildeHex).toBeUndefined();
    expect(ws.hasVfri7).toBe(false);
    expect(ws.vfri7CommitmentLog10).toBeUndefined();
    expect(ws.vfri7CommitmentLog8).toBeUndefined();
    expect(ws.nFriQueries).toBe(0);
    expect(ws.friSecurityBits).toBe(0);
  });

  it("full vfri7 witness status carries dual commitment + security fields", () => {
    const ws: WitnessStatus = {
      hasWitness: true,
      onchainCommitment: "a".repeat(32),
      maxNorms: [],
      hasVfri7: true,
      vfri7CommitmentLog10: "d".repeat(32),
      vfri7CommitmentLog8: "e".repeat(32),
      nFriQueries: 1,
      friSecurityBits: 16,
    };
    expect(ws.hasWitness).toBe(true);
    expect(ws.hasVfri7).toBe(true);
    expect(ws.vfri7CommitmentLog10).toHaveLength(32);
    expect(ws.vfri7CommitmentLog8).toHaveLength(32);
    expect(ws.nFriQueries).toBe(1);
    expect(ws.friSecurityBits).toBe(16);
  });

  it("security bits formula: 6×n+10", () => {
    const cases: Array<[number, number]> = [[1, 16], [3, 28], [20, 130]];
    for (const [n, bits] of cases) {
      const ws: WitnessStatus = {
        hasWitness: true, maxNorms: [], hasVfri7: true,
        nFriQueries: n, friSecurityBits: bits,
      };
      expect(ws.friSecurityBits).toBe(6 * ws.nFriQueries + 10);
    }
  });
});

describe("NodeStats", () => {
  it("stats shape includes FRI security fields", () => {
    const s: NodeStats = {
      transactionsReceived: 10,
      transactionsBatched: 8,
      batchesCreated: 2,
      proofsGenerated: 2,
      pending: 2,
      nFriQueries: 1,
      friSecurityBits: 16,
    };
    expect(s.proofsGenerated).toBe(2);
    expect(s.nFriQueries).toBe(1);
    expect(s.friSecurityBits).toBe(16);
  });

  it("stats security bits formula matches n_fri_queries", () => {
    const s: NodeStats = {
      transactionsReceived: 0, transactionsBatched: 0, batchesCreated: 0,
      proofsGenerated: 0, pending: 0, nFriQueries: 3, friSecurityBits: 28,
    };
    expect(s.friSecurityBits).toBe(6 * s.nFriQueries + 10);
  });
});
