import type {
  BatchStatus,
  NodeStats,
  SubmitResult,
  TransactionPayload,
  WitnessStatus,
} from "./types.js";

const HEX_RE = /^[0-9a-fA-F]+$/;

function _validateTransaction(tx: TransactionPayload): void {
  if (!tx.sender || tx.sender.length !== 64 || !HEX_RE.test(tx.sender))
    throw new TypeError("sender must be a 64-character hex string");
  if (!tx.recipient || tx.recipient.length !== 64 || !HEX_RE.test(tx.recipient))
    throw new TypeError("recipient must be a 64-character hex string");
  if (!Number.isInteger(tx.amount) || tx.amount < 0)
    throw new RangeError("amount must be a non-negative integer");
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
      has_witness?: boolean;
      witness_commitment?: string;
      has_vfri7?: boolean;
      vfri7_commitment_log10?: string;
      vfri7_commitment_log8?: string;
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
      has_witness?: boolean;
      witness_commitment?: string;
      has_vfri7?: boolean;
      vfri7_commitment_log10?: string;
      vfri7_commitment_log8?: string;
    }>("/batch/flush", {});
    if (data.status === "empty") return null;
    return this._toBatchStatus(data as Required<typeof data>);
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
        n_fri_queries?: number;
        fri_security_bits?: number;
      }>(`/batch/${batchId}/witness`);
      if (!data.has_witness) {
        return {
          hasWitness: false, maxNorms: [], hasVfri7: false,
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
        nFriQueries: data.n_fri_queries ?? 0,
        friSecurityBits: data.fri_security_bits ?? 0,
      };
    } catch {
      return null;
    }
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

  // ── Private helpers ──────────────────────────────────────────────────────

  private _toBatchStatus(data: {
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
  }): BatchStatus {
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
