import type {
  BatchListResult,
  BatchStatus,
  MempoolStatus,
  NodeConfig,
  NodeStats,
  SenderTxHistory,
  SubmitResult,
  TransactionPayload,
  TransactionStatus,
  WitnessStatus,
} from "./types.js";

/**
 * Thrown by AggregatorClient when the server returns a non-2xx HTTP response.
 * Callers can inspect `status` to distinguish 404 (not found) from 5xx errors.
 */
export class AggregatorHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "AggregatorHttpError";
  }
}

const HEX_RE = /^[0-9a-fA-F]+$/;

/** Wire format of a batch object as returned by the aggregator API (snake_case). */
interface RawBatchStatus {
  batch_id: string;
  tx_count: number;
  merkle_root: string;
  is_proven: boolean;
  stark_commitment?: string;
  has_witness?: boolean;
  witness_commitment?: string;
  has_vfri7?: boolean;
  vfri7_commitment_log10?: string;
  vfri7_commitment_log8?: string;
  has_vfri8?: boolean;
  vfri8_commitment_log10?: string;
  vfri8_commitment_log8?: string;
  has_vfri9?: boolean;
  vfri9_commitment_log10?: string;
  vfri9_commitment_log8?: string;
}

function _validateTransaction(tx: TransactionPayload): void {
  if (!tx.sender || tx.sender.length !== 64 || !HEX_RE.test(tx.sender))
    throw new TypeError("sender must be a 64-character hex string");
  if (!tx.recipient || tx.recipient.length !== 64 || !HEX_RE.test(tx.recipient))
    throw new TypeError("recipient must be a 64-character hex string");
  if (!Number.isInteger(tx.amount) || tx.amount < 1)
    throw new RangeError("amount must be a positive integer (at least 1)");
  if (!Number.isInteger(tx.nonce) || tx.nonce < 0)
    throw new RangeError("nonce must be a non-negative integer");
  if (!tx.publicKey || !HEX_RE.test(tx.publicKey))
    throw new TypeError("publicKey must be a non-empty hex string");
  if (!tx.signature || !HEX_RE.test(tx.signature))
    throw new TypeError("signature must be a non-empty hex string");
}

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
    _validateTransaction(tx);
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
      tx_hash?: string;
    }>("/transactions", body);
    return {
      accepted: data.accepted,
      mempoolSize: data.mempool_size,
      error: data.error,
      txHash: data.tx_hash,
    };
  }

  /**
   * Attempt to create a batch (respects the node's min_batch_size).
   * Returns null if there are not enough pending transactions.
   * @param proveWitnesses  When true, request VFRI7/VFRI8/VFRI9 witness generation (requires PyO3 ext).
   */
  async runCycle(proveWitnesses = false): Promise<BatchStatus | null> {
    const path = proveWitnesses ? "/batch/run?prove_witnesses=true" : "/batch/run";
    const data = await this._post<{ status: string } & Partial<RawBatchStatus>>(path, {});
    if (data.status === "no_batch") return null;
    return this._toBatchStatus(data as RawBatchStatus);
  }

  /**
   * Force a batch from whatever is in the mempool.
   * Returns null if the mempool is empty.
   * @param proveWitnesses  When true, request VFRI7/VFRI8/VFRI9 witness generation (requires PyO3 ext).
   */
  async flush(proveWitnesses = false): Promise<BatchStatus | null> {
    const path = proveWitnesses ? "/batch/flush?prove_witnesses=true" : "/batch/flush";
    const data = await this._post<{ status: string } & Partial<RawBatchStatus>>(path, {});
    if (data.status === "empty") return null;
    return this._toBatchStatus(data as RawBatchStatus);
  }

  /**
   * Retrieve the witness status for a batch from the aggregator.
   * Returns null if the batch had no witness proof.
   */
  async getWitnessStatus(batchId: string): Promise<WitnessStatus | null> {
    try {
      const data = await this._get<{
        has_witness: boolean;
        onchain_commitment?: string;
        c_tilde_hex?: string;
        max_norms?: number[];
        has_vfri7?: boolean;
        vfri7_commitment_log10?: string;
        vfri7_commitment_log8?: string;
        has_vfri8?: boolean;
        vfri8_commitment_log10?: string;
        vfri8_commitment_log8?: string;
        has_vfri9?: boolean;
        vfri9_commitment_log10?: string;
        vfri9_commitment_log8?: string;
        n_fri_queries?: number;
        fri_security_bits?: number;
      }>(`/batch/${batchId}/witness`);
      if (!data.has_witness) {
        return {
          hasWitness: false, maxNorms: [],
          hasVfri7: false, hasVfri8: false, hasVfri9: false,
          nFriQueries: data.n_fri_queries ?? 0,
          friSecurityBits: data.fri_security_bits ?? 0,
        };
      }
      return {
        hasWitness: true,
        onchainCommitment: data.onchain_commitment,
        cTildeHex: data.c_tilde_hex,
        maxNorms: data.max_norms ?? [],
        hasVfri7: data.has_vfri7 ?? false,
        vfri7CommitmentLog10: data.vfri7_commitment_log10,
        vfri7CommitmentLog8: data.vfri7_commitment_log8,
        hasVfri8: data.has_vfri8 ?? false,
        vfri8CommitmentLog10: data.vfri8_commitment_log10,
        vfri8CommitmentLog8: data.vfri8_commitment_log8,
        hasVfri9: data.has_vfri9 ?? false,
        vfri9CommitmentLog10: data.vfri9_commitment_log10,
        vfri9CommitmentLog8: data.vfri9_commitment_log8,
        nFriQueries: data.n_fri_queries ?? 0,
        friSecurityBits: data.fri_security_bits ?? 0,
      };
    } catch (e) {
      if (e instanceof AggregatorHttpError && (e.status === 404 || e.status === 400)) return null;
      throw e;
    }
  }

  /**
   * Retrieve the status of a specific batch by ID.
   * Returns null if the batch is not found (HTTP 404) or the ID is invalid (HTTP 400).
   * Re-throws on network errors and server errors (5xx) so callers detect outages.
   */
  async getBatch(batchId: string): Promise<BatchStatus | null> {
    try {
      const data = await this._get<RawBatchStatus>(`/batch/${batchId}`);
      return this._toBatchStatus(data);
    } catch (e) {
      if (e instanceof AggregatorHttpError && (e.status === 404 || e.status === 400)) return null;
      throw e;
    }
  }

  /**
   * Return recent batches from the aggregator, newest first.
   *
   * @param limit   Maximum number of batches to return (1–200, default 50).
   * @param proven  When set, filter to only proven (`true`) or unproven (`false`) batches.
   */
  async listBatches(limit = 50, proven?: boolean): Promise<BatchListResult> {
    let path = `/batches?limit=${limit}`;
    if (proven !== undefined) path += `&proven=${proven}`;
    const data = await this._get<{
      batches: RawBatchStatus[];
      total: number;
    }>(path);
    return {
      batches: data.batches.map(b => this._toBatchStatus(b)),
      total: data.total,
    };
  }

  /**
   * Return the transaction history for a sender address (pending + batched, newest-first).
   *
   * @param sender  64-char hex address (SHA3-256 of the public key).
   * @param limit   Maximum number of tx hashes to return (1–1000, default 100).
   */
  async getAddressTransactions(sender: string, limit = 100): Promise<SenderTxHistory> {
    const data = await this._get<{
      sender: string;
      tx_hashes: string[];
      pending_count: number;
      total: number;
      limit: number;
    }>(`/address/${sender}/transactions?limit=${limit}`);
    return {
      sender: data.sender,
      txHashes: data.tx_hashes,
      pendingCount: data.pending_count,
      total: data.total,
      limit: data.limit,
    };
  }

  /**
   * Look up a transaction by its 64-char hex SHA3-256 hash.
   *
   * Returns a {@link TransactionStatus} with `status` set to:
   * - `"pending"`  — in the mempool, not yet batched
   * - `"batched"`  — included in a batch; `batchId` is set
   * - `"unknown"`  — not found in the mempool or recent history (404 → unknown)
   */
  async getTransaction(txHash: string): Promise<TransactionStatus> {
    try {
      const data = await this._get<{
        tx_hash: string;
        status: "pending" | "batched";
        batch_id?: string;
      }>(`/transaction/${txHash}`);
      return {
        txHash: data.tx_hash,
        status: data.status,
        batchId: data.batch_id,
      };
    } catch (e) {
      if (e instanceof AggregatorHttpError && e.status === 404) {
        return { txHash, status: "unknown" };
      }
      throw e;
    }
  }

  /**
   * Return a snapshot of the current mempool.
   *
   * `limit` (1–1000) caps how many tx hashes are returned (default 100).
   */
  async getMempool(limit = 100): Promise<MempoolStatus> {
    const data = await this._get<{
      size: number;
      capacity: number;
      tx_hashes: string[];
    }>(`/mempool?limit=${limit}`);
    return {
      size: data.size,
      capacity: data.capacity,
      txHashes: data.tx_hashes,
    };
  }

  /**
   * Return the ordered list of transaction hashes in a batch, or `null` if not found.
   *
   * Returns `null` on HTTP 404 (batch not in recent history).
   */
  async getBatchTransactions(batchId: string): Promise<string[] | null> {
    try {
      const data = await this._get<{
        batch_id: string;
        tx_count: number;
        tx_hashes: string[];
      }>(`/batch/${batchId}/transactions`);
      return data.tx_hashes;
    } catch (e) {
      if (e instanceof AggregatorHttpError && (e.status === 404 || e.status === 400)) {
        return null;
      }
      throw e;
    }
  }

  /** Retrieve static node configuration (security level, batch size limits). */
  async getNodeConfig(): Promise<NodeConfig> {
    const data = await this._get<{
      n_fri_queries: number;
      fri_security_bits: number;
      min_batch_size: number;
      max_batch_size: number;
      mempool_capacity: number;
      version: string;
    }>("/node/config");
    return {
      nFriQueries: data.n_fri_queries,
      friSecurityBits: data.fri_security_bits,
      minBatchSize: data.min_batch_size,
      maxBatchSize: data.max_batch_size,
      mempoolCapacity: data.mempool_capacity,
      version: data.version,
    };
  }

  /** Retrieve aggregator node statistics. */
  async stats(): Promise<NodeStats> {
    const data = await this._get<{
      transactions_received: number;
      transactions_batched: number;
      batches_created: number;
      proofs_generated: number;
      pending: number;
      n_fri_queries?: number;
      fri_security_bits?: number;
    }>("/stats");
    return {
      transactionsReceived: data.transactions_received,
      transactionsBatched: data.transactions_batched,
      batchesCreated: data.batches_created,
      proofsGenerated: data.proofs_generated,
      pending: data.pending,
      nFriQueries: data.n_fri_queries ?? 1,
      friSecurityBits: data.fri_security_bits ?? 16,
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

  /**
   * Poll GET /batch/{id} until the batch is found or the timeout is reached.
   * Throws {@link Error} if the batch is not found within `timeoutMs`.
   */
  async waitForBatch(
    batchId: string,
    options: { timeoutMs?: number; pollIntervalMs?: number } = {},
  ): Promise<BatchStatus> {
    const { timeoutMs = 60_000, pollIntervalMs = 2_000 } = options;
    if (timeoutMs <= 0) throw new Error("timeoutMs must be positive");
    if (pollIntervalMs <= 0) throw new Error("pollIntervalMs must be positive");
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const status = await this.getBatch(batchId);
      if (status !== null) return status;
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error(`Batch ${batchId} not found after ${timeoutMs} ms`);
      }
      await new Promise<void>((resolve) =>
        setTimeout(resolve, Math.min(pollIntervalMs, remaining)),
      );
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private _toBatchStatus(data: RawBatchStatus): BatchStatus {
    return {
      batchId: data.batch_id,
      txCount: data.tx_count,
      merkleRoot: data.merkle_root,
      isProven: data.is_proven,
      starkCommitment: data.stark_commitment,
      hasWitness: data.has_witness ?? false,
      witnessCommitment: data.witness_commitment,
      hasVfri7: data.has_vfri7 ?? false,
      vfri7CommitmentLog10: data.vfri7_commitment_log10,
      vfri7CommitmentLog8: data.vfri7_commitment_log8,
      hasVfri8: data.has_vfri8 ?? false,
      vfri8CommitmentLog10: data.vfri8_commitment_log10,
      vfri8CommitmentLog8: data.vfri8_commitment_log8,
      hasVfri9: data.has_vfri9 ?? false,
      vfri9CommitmentLog10: data.vfri9_commitment_log10,
      vfri9CommitmentLog8: data.vfri9_commitment_log8,
    };
  }

  private async _post<T>(path: string, body: unknown): Promise<T> {
    return this._request<T>(path, { method: "POST", body: JSON.stringify(body) });
  }

  private async _get<T>(path: string): Promise<T> {
    return this._request<T>(path, { method: "GET" });
  }

  private async _request<T>(path: string, init: RequestInit): Promise<T> {
    if (this.timeoutMs <= 0) throw new RangeError("timeoutMs must be positive");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.baseUrl + path, {
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        ...init,
      });
      // Read body as text once — avoids double-consumption when both the error
      // branch and the JSON parse branch need the body.
      const text = await res.text().catch(() => "");
      if (!res.ok) {
        throw new AggregatorHttpError(
          res.status,
          `HTTP ${res.status} ${res.statusText}: ${text}`,
        );
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        // Proxy/CDN returned HTML with 2xx (e.g. nginx restart page).
        throw new Error(
          `Aggregator ${path} returned non-JSON body: ${text.slice(0, 200)}`,
        );
      }
    } finally {
      clearTimeout(timer);
    }
  }
}
