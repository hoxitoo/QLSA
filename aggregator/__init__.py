"""
QLSA Aggregator — Phase 4.

Collects signed transactions, batches them, runs the STARK prover,
and prepares BatchResult for on-chain submission via BatchRegistry.

Usage:
    from aggregator.node import AggregatorNode
    node = AggregatorNode(min_batch_size=10)
    node.submit(signed_tx)
    result = node.run_cycle()   # returns BatchResult or None
"""
