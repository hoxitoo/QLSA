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
    };
    expect(s.isProven).toBe(true);
    expect(s.hasWitness).toBe(true);
    expect(s.witnessCommitment).toHaveLength(32);
  });

  it("unproven batch has optional fields undefined", () => {
    const s: BatchStatus = {
      batchId: "xyz",
      txCount: 2,
      merkleRoot: "a".repeat(128),
      isProven: false,
      hasWitness: false,
    };
    expect(s.starkCommitment).toBeUndefined();
    expect(s.witnessCommitment).toBeUndefined();
  });
});

describe("WitnessStatus", () => {
  it("no-witness status has empty maxNorms", () => {
    const ws: WitnessStatus = { hasWitness: false, maxNorms: [] };
    expect(ws.hasWitness).toBe(false);
    expect(ws.maxNorms).toHaveLength(0);
    expect(ws.onchainCommitment).toBeUndefined();
    expect(ws.cTildeHex).toBeUndefined();
  });

  it("full witness status carries all fields", () => {
    const ws: WitnessStatus = {
      hasWitness: true,
      onchainCommitment: "a".repeat(32),
      cTildeHex: "b".repeat(96),
      maxNorms: [123_456, 234_567, 345_678, 456_789, 500_000],
    };
    expect(ws.hasWitness).toBe(true);
    expect(ws.onchainCommitment).toHaveLength(32);
    expect(ws.cTildeHex).toHaveLength(96);
    expect(ws.maxNorms).toHaveLength(5);
  });
});

describe("NodeStats", () => {
  it("stats shape is correct", () => {
    const s: NodeStats = {
      transactionsReceived: 10,
      transactionsBatched: 8,
      batchesCreated: 2,
      proofsGenerated: 2,
      pending: 2,
    };
    expect(s.proofsGenerated).toBe(2);
  });
});
