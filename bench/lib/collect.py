#!/usr/bin/env python3
"""Join per-participant probe outputs into one metric document.

Usage: collect.py --metric b01_cold_start --label "..." name1 file1 name2 file2 ...

The aggregate keeps each participant's argv, server_info and summary, plus
pointers to the raw files (which carry every per-run sample).
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metric", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("pairs", nargs="+", help="name file name file ...")
    args = ap.parse_args()

    if len(args.pairs) % 2 != 0:
        ap.error("need name/file pairs")

    participants = {}
    for i in range(0, len(args.pairs), 2):
        name, path = args.pairs[i], args.pairs[i + 1]
        with open(path) as f:
            doc = json.load(f)
        participants[name] = {
            "raw_file": path,
            "argv": doc.get("argv"),
            "transport": doc.get("transport"),
            "server_info": doc.get("server_info"),
            "runs": doc.get("runs"),
            "failures": doc.get("failures", doc.get("failures_count", 0)),
            "summary": doc.get("summary"),
        }

    print(json.dumps({
        "metric": args.metric,
        "label": args.label,
        "participants": participants,
    }, indent=1))


if __name__ == "__main__":
    main()
