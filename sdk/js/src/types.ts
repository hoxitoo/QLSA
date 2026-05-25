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
}

export interface WitnessStatus {
  hasWitness: boolean;
  onchainCommitment?: string;  // 32-char hex (16-byte Blake2s binding)
  cTildeHex?: string;          // 96-char hex (48-byte ML-DSA-65 LAMBDA_BYTES)
  maxNorms: number[];
  // VFRI7 cross-bound ML-DSA V23 proof commitments (MVP-5)
  hasVfri7: boolean;
  vfri7CommitmentLog10?: string;  // 32-char hex (16-byte binding, LOG=10 group)
  vfri7CommitmentLog8?: string;   // 32-char hex (16-byte binding, LOG=8 group)
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
}
