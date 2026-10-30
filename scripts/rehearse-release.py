#!/usr/bin/env python3
"""Rehearse an approved full private export locally. Never connects to Cloudflare."""

import argparse
from release_rehearsal import BASELINES, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Approved full SQL export outside the repository")
    parser.add_argument("--sequences", required=True, help="Private JSON object mapping every AUTOINCREMENT table to its captured sequence")
    parser.add_argument("--baseline", required=True, type=int, choices=BASELINES, help="Independently verified applied schema (5, 6, or 7)")
    parser.add_argument("--output-dir", required=True, help="NEW private directory; never reused or overwritten")
    args = parser.parse_args()
    try:
        run(args.source, args.sequences, args.baseline, args.output_dir)
    except Exception:
        parser.exit(1, "FAIL offline rehearsal. Check private inputs/baseline; retain any partial copy and use a new output directory after diagnosis.\n")
    print("PASS offline SQLite rehearsal only; private result retained. No remote effects or rollout approval.\n"
          "Still required: current-copy provenance, workerd/old-reader rehearsal, staging, live cache/Access, browsers and explicit approvals.")


if __name__ == "__main__":
    main()
