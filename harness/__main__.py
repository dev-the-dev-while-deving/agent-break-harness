"""CLI: python -m harness run | repro | serve"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness", description="Agent Break Harness (Track 08)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Run the golden suite and write reports/")
    run_p.add_argument("--target", choices=("victim", "hardened", "both"), default="both")

    rp = sub.add_parser("repro", help="Re-run one report id")
    rp.add_argument("--id", required=True)
    rp.add_argument("--seed", type=int, default=None)

    sp = sub.add_parser("serve", help="Dashboard on :8000")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)

    if args.cmd == "run":
        from harness.runner import run_suite

        reports = run_suite(target=args.target)
        fails = sum(1 for r in reports if r["verdict"] == "fail")
        print(f"{'id':<36} {'target':<10} {'verdict':<6} severity")
        for r in reports:
            print(f"{r['id']:<36} {r['target']:<10} {r['verdict']:<6} {r.get('severity') or '-'}")
        print(f"\n{fails} fail / {len(reports) - fails} pass  (fail = vulnerability; not a CI blocker)")
        return 0

    if args.cmd == "repro":
        from harness.runner import repro

        report = repro(args.id, seed=args.seed)
        print(json.dumps(report, indent=2))
        return 0

    if args.cmd == "serve":
        import uvicorn
        from harness.serve import app

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # harness crash only
        print(f"harness crash: {exc}", file=sys.stderr)
        raise
