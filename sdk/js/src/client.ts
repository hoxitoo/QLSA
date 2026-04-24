import type {
  BatchStatus,
  NodeStats,
  SubmitResult,
  TransactionPayload,
} from "./types.js";

export class AggregatorClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  /**
   * @param baseUrl   Base URL of the QLSA aggregator API, e.g. "http://localhost:8000"
   * @param timeoutMs Request timeout in milliseconds (default: 30 000)
   */
  constructor(baseUrl: string, timeoutMs = 30_000) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
  }

  /** Submit a signed transaction to the aggregator mempool. */
  async submit(tx: TransactionPayload): Promise<SubmitResult> {
    const body = {
      sender: tx.sender,
      recipient: tx.recipient,
      amount: tx.amount,
      nonce: tx.nonce,
      public_key: tx.publicKey,
      signature: tx.signature,
    };
    const data = await this._post<{
      accepted: boolean;
      mempool_size: number;
      error?: string;
    }>("/transactions", body);
    return {
      accepted: data.accepted,
      mempoolSize: data.mempool_size,
      error: data.error,
    };
  }

  /**
   * Attempt to create a batch (respects the node's min_batch_size).
   * Returns null if there are not enough pending transactions.
   */
  async runCycle(): Promise<BatchStatus | null> {
    const data = await this._post<{
      status: string;
      batch_id?: string;
      tx_count?: number;
      merkle_root?: string;
      is_proven?: boolean;
      stark_commitment?: string;
    }>("/batch/run", {});
    if (data.status === "no_batch") return null;
    return this._toBatchStatus(data as Required<typeof data>);
  }

  /**
   * Force a batch from whatever is in the mempool.
   * Returns null if the mempool is empty.
   */
  async flush(): Promise<BatchStatus | null> {
    const data = await this._post<{
      status: string;
      batch_id?: string;
      tx_count?: number;
      merkle_root?: string;
      is_proven?: boolean;
      stark_commitment?: string;
    }>("/batch/flush", {});
    if (data.status === "empty") return null;
    return this._toBatchStatus(data as Required<typeof data>);
  }

  /** Retrieve aggregator node statistics. */
  async stats(): Promise<NodeStats> {
    const data = await this._get<{
      transactions_received: number;
      transactions_batched: number;
      batches_created: number;
      proofs_generated: number;
      pending: number;
    }>("/stats");
    return {
      transactionsReceived: data.transactions_received,
      transactionsBatched: data.transactions_batched,
      batchesCreated: data.batches_created,
      proofsGenerated: data.proofs_generated,
      pending: data.pending,
    };
  }

  /** Returns true if the aggregator is reachable and healthy. */
  async health(): Promise<boolean> {
    try {
      const data = await this._get<{ status: string }>("/health");
      return data.status === "ok";
    } catch {
      return false;
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private _toBatchStatus(data: {
    batch_id: string;
    tx_count: number;
    merkle_root: string;
    is_proven: boolean;
    stark_commitment?: string;
  }): BatchStatus {
    return {
      batchId: data.batch_id,
      txCount: data.tx_count,
      merkleRoot: data.merkle_root,
      isProven: data.is_proven,
      starkCommitment: data.stark_commitment,
    };
  }

  private async _post<T>(path: string, body: unknown): Promise<T> {
    return this._request<T>(path, { method: "POST", body: JSON.stringify(body) });
  }

  private async _get<T>(path: string): Promise<T> {
    return this._request<T>(path, { method: "GET" });
  }

  private async _request<T>(path: string, init: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.baseUrl + path, {
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        ...init,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`HTTP ${res.status} ${res.statusText}: ${text}`);
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}
