export interface TransactionPayload {
  sender: string;      // 64-char hex address
  recipient: string;   // 64-char hex address
  amount: number;
  nonce: number;
  publicKey: string;   // hex-encoded ML-DSA public key
  signature: string;   // hex-encoded ML-DSA signature
}

export interface SubmitResult {
  accepted: boolean;
  mempoolSize: number;
  error?: string;
  /** 64-char hex SHA3-256 hash; set when accepted is true. */
  txHash?: string;
}

/**
 * Lifecycle status of a submitted transaction.
 *
 * `status` is one of:
 * - `"pending"`  — in the mempool, not yet batched
 * - `"batched"`  — included in a batch; `batchId` is set
 * - `"unknown"`  — not found in mempool or recent history
 */
export interface TransactionStatus {
  txHash: string;
  status: "pending" | "batched" | "unknown";
  batchId?: string;
}

export interface WitnessStatus {
  hasWitness: boolean;
  onchainCommitment?: string;  // 32-char hex — alias for vfri7CommitmentLog10 (backward compat)
  cTildeHex?: string;          // 96-char hex — legacy V3/V4 path only; undefined for VFRI7
  maxNorms: number[];          // legacy V3/V4 path only; empty for VFRI7
  // VFRI7 cross-bound ML-DSA V23 proof commitments (MVP-5)
  hasVfri7: boolean;
  vfri7CommitmentLog10?: string;  // 32-char hex (16-byte binding, LOG=10 group)
  vfri7CommitmentLog8?: string;   // 32-char hex (16-byte binding, LOG=8 group)
  nFriQueries: number;            // FRI queries used; 0 = extension not available
  friSecurityBits: number;        // 6 × nFriQueries + 10
}

export interface BatchStatus {
  batchId: string;
  txCount: number;
  merkleRoot: string;       // hex (128 chars for SHA3-512)
  isProven: boolean;
  starkCommitment?: string;
  hasWitness: boolean;
  witnessCommitment?: string;  // 32-char hex (16-byte binding for tx[0])
  // VFRI7 cross-bound ML-DSA V23 proof commitments (MVP-5)
  hasVfri7: boolean;
  vfri7CommitmentLog10?: string;  // 32-char hex (16-byte binding, LOG=10 group)
  vfri7CommitmentLog8?: string;   // 32-char hex (16-byte binding, LOG=8 group)
}

export interface NodeStats {
  transactionsReceived: number;
  transactionsBatched: number;
  batchesCreated: number;
  proofsGenerated: number;
  pending: number;
  nFriQueries: number;      // configured FRI queries per proof group
  friSecurityBits: number;  // 6 × nFriQueries + 10
}

export interface NodeConfig {
  nFriQueries: number;      // FRI queries per proof group (on-chain security parameter)
  friSecurityBits: number;  // 6 × nFriQueries + 10
  minBatchSize: number;     // minimum transactions required to create a batch
  maxBatchSize: number;     // maximum transactions per batch
  mempoolCapacity: number;  // maximum transactions held in the mempool
  version: string;          // aggregator API version
}

/** Response from GET /batches (via AggregatorClient.listBatches). */
export interface BatchListResult {
  /** Recent batches, newest first (up to `limit` items). */
  batches: BatchStatus[];
  /** Total number of batches held in the node's in-memory history. */
  total: number;
}

/** Snapshot of the aggregator mempool (GET /mempool). */
export interface MempoolStatus {
  /** Current number of pending transactions. */
  size: number;
  /** Maximum mempool capacity configured on this node. */
  capacity: number;
  /** First `min(size, limit)` pending tx hashes in FIFO order (64-char hex). */
  txHashes: string[];
}
