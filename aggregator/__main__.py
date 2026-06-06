"""
Run the QLSA Aggregator HTTP server.

Usage:
    python -m aggregator [--host HOST] [--port PORT] [--reload]

Environment variables:
    HOST              Bind address (default: 0.0.0.0)
    PORT              Bind port (default: 8000)
    N_FRI_QUERIES     FRI queries per proof group, 1–64 (default: 1)
    TRUSTED_PROXIES   Comma-separated list of trusted proxy IPs

Examples:
    python -m aggregator
    python -m aggregator --port 9000
    N_FRI_QUERIES=3 python -m aggregator --host 127.0.0.1
"""
from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="QLSA Aggregator HTTP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "0.0.0.0"),  # nosec B104
        help="Bind address (default: 0.0.0.0, env: HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8000")),
        help="Bind port (default: 8000, env: PORT)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes (development mode only)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level (default: info)",
    )
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is required to run the aggregator server.\n"
            "Install it with: pip install uvicorn[standard]",
            file=sys.stderr,
        )
        return 1

    print(
        f"Starting QLSA Aggregator on http://{args.host}:{args.port} "
        f"(N_FRI_QUERIES={os.environ.get('N_FRI_QUERIES', '1')})"
    )

    uvicorn.run(
        "aggregator.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
