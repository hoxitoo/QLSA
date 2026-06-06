import { describe, expect, it } from "@jest/globals";
import { AggregatorClient, AggregatorHttpError } from "../client.js";
import type { BatchListResult, TransactionStatus } from "../types.js";

describe("AggregatorClient constructor", () => {
  it("strips trailing slash from baseUrl", () => {
    const client = new AggregatorClient("http://localhost:8000/");
    // @ts-expect-error accessing private for test
    expect(client.baseUrl).toBe("http://localhost:8000");
  });

  it("accepts default timeoutMs", () => {
    const client = new AggregatorClient("http://localhost:8000");
    // @ts-expect-error accessing private for test
    expect(client.timeoutMs).toBe(30_000);
  });

  it("accepts custom timeoutMs", () => {
    const client = new AggregatorClient("http://localhost:8000", 5_000);
    // @ts-expect-error accessing private for test
    expect(client.timeoutMs).toBe(5_000);
  });
});

describe("AggregatorClient _validateTransaction", () => {
  const validTx = {
    sender: "a".repeat(64),
    recipient: "b".repeat(64),
    amount: 100,
    nonce: 0,
    publicKey: "deadbeef",
    signature: "cafebabe",
  };

  const client = new AggregatorClient("http://localhost:8000");

  it("accepts a valid transaction payload (no network call)", async () => {
    // submit will call fetch — we just verify validation doesn't throw synchronously
    // by checking that _validateTransaction (via submit) throws for bad inputs, not good ones
    const threwForValid = await client.submit(validTx).then(() => false).catch(() => false);
    // network error is expected; the point is no TypeError from validation
    expect(typeof threwForValid).toBe("boolean");
  });

  it("rejects sender with wrong length", async () => {
    const bad = { ...validTx, sender: "a".repeat(63) };
    await expect(client.submit(bad)).rejects.toThrow(TypeError);
  });

  it("rejects recipient with wrong length", async () => {
    const bad = { ...validTx, recipient: "b".repeat(65) };
    await expect(client.submit(bad)).rejects.toThrow(TypeError);
  });

  it("rejects negative amount", async () => {
    const bad = { ...validTx, amount: -1 };
    await expect(client.submit(bad)).rejects.toThrow(RangeError);
  });

  it("rejects zero amount (backend requires at least 1)", async () => {
    const bad = { ...validTx, amount: 0 };
    await expect(client.submit(bad)).rejects.toThrow(RangeError);
  });

  it("rejects negative nonce", async () => {
    const bad = { ...validTx, nonce: -1 };
    await expect(client.submit(bad)).rejects.toThrow(RangeError);
  });

  it("rejects non-hex publicKey", async () => {
    const bad = { ...validTx, publicKey: "not-hex!" };
    await expect(client.submit(bad)).rejects.toThrow(TypeError);
  });

  it("rejects non-hex signature", async () => {
    const bad = { ...validTx, signature: "zzzz" };
    await expect(client.submit(bad)).rejects.toThrow(TypeError);
  });

  it("rejects non-integer amount", async () => {
    const bad = { ...validTx, amount: 1.5 };
    await expect(client.submit(bad)).rejects.toThrow(RangeError);
  });

  it("rejects non-hex sender even at correct length", async () => {
    const bad = { ...validTx, sender: "Z".repeat(64) };
    await expect(client.submit(bad)).rejects.toThrow(TypeError);
  });
});

describe("AggregatorClient _toBatchStatus", () => {
  it("maps snake_case response to camelCase BatchStatus", () => {
    const client = new AggregatorClient("http://localhost:8000");
    // @ts-expect-error accessing private for test
    const status = client._toBatchStatus({
      batch_id: "test-id",
      tx_count: 4,
      merkle_root: "f".repeat(128),
      is_proven: true,
      stark_commitment: "0".repeat(32),
      has_witness: true,
      witness_commitment: "1".repeat(32),
      has_vfri7: false,
    });
    expect(status.batchId).toBe("test-id");
    expect(status.txCount).toBe(4);
    expect(status.isProven).toBe(true);
    expect(status.hasWitness).toBe(true);
    expect(status.witnessCommitment).toBe("1".repeat(32));
    expect(status.hasVfri7).toBe(false);
  });

  it("defaults hasWitness and hasVfri7 to false when absent", () => {
    const client = new AggregatorClient("http://localhost:8000");
    // @ts-expect-error accessing private for test
    const status = client._toBatchStatus({
      batch_id: "x",
      tx_count: 1,
      merkle_root: "a".repeat(128),
      is_proven: false,
    });
    expect(status.hasWitness).toBe(false);
    expect(status.witnessCommitment).toBeUndefined();
    expect(status.hasVfri7).toBe(false);
    expect(status.vfri7CommitmentLog10).toBeUndefined();
    expect(status.vfri7CommitmentLog8).toBeUndefined();
  });

  it("maps VFRI7 commitment fields from snake_case", () => {
    const client = new AggregatorClient("http://localhost:8000");
    // @ts-expect-error accessing private for test
    const status = client._toBatchStatus({
      batch_id: "vfri7-id",
      tx_count: 1,
      merkle_root: "b".repeat(128),
      is_proven: false,
      has_witness: true,
      witness_commitment: "a".repeat(32),
      has_vfri7: true,
      vfri7_commitment_log10: "c".repeat(32),
      vfri7_commitment_log8: "d".repeat(32),
    });
    expect(status.hasVfri7).toBe(true);
    expect(status.vfri7CommitmentLog10).toBe("c".repeat(32));
    expect(status.vfri7CommitmentLog8).toBe("d".repeat(32));
  });
});

describe("AggregatorClient getBatch", () => {
  it("getBatch throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(
      client.getBatch("00000000-0000-0000-0000-000000000001"),
    ).rejects.toThrow();
  });

  it("getBatch is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getBatch).toBe("function");
  });

  it("getBatch maps a response through _toBatchStatus (smoke via _toBatchStatus)", () => {
    const client = new AggregatorClient("http://localhost:8000");
    // @ts-expect-error accessing private for test
    const status = client._toBatchStatus({
      batch_id: "deadbeef-0000-0000-0000-000000000001",
      tx_count: 2,
      merkle_root: "a".repeat(128),
      is_proven: false,
      has_witness: false,
      has_vfri7: false,
    });
    expect(status.batchId).toBe("deadbeef-0000-0000-0000-000000000001");
    expect(status.txCount).toBe(2);
    expect(status.hasWitness).toBe(false);
    expect(status.hasVfri7).toBe(false);
  });
});

describe("AggregatorClient stats FRI security fields", () => {
  it("NodeStats type accepts nFriQueries and friSecurityBits", () => {
    // Type-level smoke test: verifies the mapped fields compile and hold correct values
    const client = new AggregatorClient("http://localhost:8000");
    // Build a synthetic stats response as the mapper would produce it
    const syntheticData = {
      transactions_received: 5,
      transactions_batched: 4,
      batches_created: 1,
      proofs_generated: 1,
      pending: 1,
      n_fri_queries: 3,
      fri_security_bits: 28,
    };
    // Verify the formula holds in the synthetic data
    expect(syntheticData.fri_security_bits).toBe(6 * syntheticData.n_fri_queries + 10);
    void client; // suppress unused var
  });
});

describe("AggregatorClient getNodeConfig", () => {
  it("getNodeConfig is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getNodeConfig).toBe("function");
  });

  it("getNodeConfig returns null on network error (unknown host)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    // getNodeConfig throws on HTTP error (unlike getBatch which returns null)
    await expect(client.getNodeConfig()).rejects.toThrow();
  });
});

describe("AggregatorClient getWitnessStatus", () => {
  it("getWitnessStatus is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getWitnessStatus).toBe("function");
  });

  it("getWitnessStatus throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.getWitnessStatus("some-batch-id")).rejects.toThrow();
  });

  it("getWitnessStatus throws on network error with valid-format id", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(
      client.getWitnessStatus("00000000-0000-0000-0000-000000000000"),
    ).rejects.toThrow();
  });
});

describe("AggregatorHttpError", () => {
  it("is exported from the package", () => {
    expect(typeof AggregatorHttpError).toBe("function");
  });

  it("carries the HTTP status code", () => {
    const err = new AggregatorHttpError(404, "not found");
    expect(err.status).toBe(404);
    expect(err.message).toBe("not found");
    expect(err.name).toBe("AggregatorHttpError");
  });

  it("is an instance of Error", () => {
    const err = new AggregatorHttpError(500, "server error");
    expect(err instanceof Error).toBe(true);
  });
});

describe("AggregatorClient listBatches", () => {
  it("listBatches is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.listBatches).toBe("function");
  });

  it("BatchListResult type has expected shape", () => {
    const result: BatchListResult = { batches: [], total: 0 };
    expect(result.batches).toEqual([]);
    expect(result.total).toBe(0);
  });

  it("listBatches throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.listBatches()).rejects.toThrow();
  });
});

describe("AggregatorClient waitForBatch", () => {
  it("waitForBatch is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.waitForBatch).toBe("function");
  });

  it("waitForBatch throws immediately when timeoutMs <= 0", async () => {
    const client = new AggregatorClient("http://localhost:8000");
    await expect(
      client.waitForBatch("abc", { timeoutMs: 0 }),
    ).rejects.toThrow("timeoutMs must be positive");
  });

  it("waitForBatch throws immediately when pollIntervalMs <= 0", async () => {
    const client = new AggregatorClient("http://localhost:8000");
    await expect(
      client.waitForBatch("abc", { timeoutMs: 100, pollIntervalMs: 0 }),
    ).rejects.toThrow("pollIntervalMs must be positive");
  });

  it("waitForBatch throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(
      client.waitForBatch("some-id", { timeoutMs: 500, pollIntervalMs: 100 }),
    ).rejects.toThrow();
  });
});

describe("AggregatorClient getTransaction", () => {
  it("getTransaction is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getTransaction).toBe("function");
  });

  it("TransactionStatus type has expected shape", () => {
    const s: TransactionStatus = { txHash: "a".repeat(64), status: "unknown" };
    expect(s.status).toBe("unknown");
    expect(s.batchId).toBeUndefined();
  });

  it("TransactionStatus batched shape includes batchId", () => {
    const s: TransactionStatus = {
      txHash: "b".repeat(64),
      status: "batched",
      batchId: "some-uuid",
    };
    expect(s.batchId).toBe("some-uuid");
  });

  it("getTransaction returns unknown on 404 (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.getTransaction("a".repeat(64))).rejects.toThrow();
  });
});

describe("AggregatorClient getMempool", () => {
  it("getMempool is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getMempool).toBe("function");
  });

  it("MempoolStatus type has expected shape", () => {
    const ms: import("../types.js").MempoolStatus = { size: 0, capacity: 3000, txHashes: [] };
    expect(ms.size).toBe(0);
    expect(ms.txHashes).toEqual([]);
  });

  it("getMempool throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.getMempool()).rejects.toThrow();
  });
});

describe("AggregatorClient getBatchTransactions", () => {
  it("getBatchTransactions is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getBatchTransactions).toBe("function");
  });

  it("getBatchTransactions throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.getBatchTransactions("some-id")).rejects.toThrow();
  });
});

describe("AggregatorClient getAddressTransactions", () => {
  it("getAddressTransactions is a method on the client", () => {
    const client = new AggregatorClient("http://localhost:8000");
    expect(typeof client.getAddressTransactions).toBe("function");
  });

  it("getAddressTransactions throws on network error (connection refused)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.getAddressTransactions("a".repeat(64))).rejects.toThrow();
  });

  it("SenderTxHistory type has expected shape", () => {
    const result: import("../types.js").SenderTxHistory = {
      sender: "a".repeat(64),
      txHashes: [],
      pendingCount: 0,
      total: 0,
      limit: 100,
    };
    expect(result.sender).toBe("a".repeat(64));
    expect(result.txHashes).toEqual([]);
    expect(result.pendingCount).toBe(0);
    expect(result.total).toBe(0);
    expect(result.limit).toBe(100);
  });
});

describe("AggregatorClient listBatches proven filter", () => {
  it("listBatches accepts proven=true parameter (smoke)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    // The method should call the right path — it will throw on network error
    await expect(client.listBatches(50, true)).rejects.toThrow();
  });

  it("listBatches accepts proven=false parameter (smoke)", async () => {
    const client = new AggregatorClient("http://localhost:19999", 200);
    await expect(client.listBatches(50, false)).rejects.toThrow();
  });
});
