#!/usr/bin/env python3
"""Render a compact markdown summary from bench/results/*.json.

Reads the aggregates produced by the b-scripts and prints tables:
- b01 cold start (median/mean/sigma/min/max, CV flag)
- b03 idle RSS (median/max, MiB)
- b05 exec latency (p50/p95/p99)
- b07 per-connection memory
- b08 footprint

Every number traces to the JSON files; this is a renderer, not a calculator.
"""
import json
import os
import sys

RESULTS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "results")

NAMES = {"ours": "mcp-node-zig", "tumf": "tumf/mcp-shell-server", "g0t4": "g0t4/mcp-server-commands"}


def load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def fmt(v, nd=1):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def cv_flag(summary):
    if not summary or summary.get("cv_pct") is None:
        return ""
    return " (!)" if summary["cv_pct"] > 10 else ""


def main():
    out = []
    out.append("# bench results summary\n")

    b01 = load("b01_cold_start.json")
    if b01:
        out.append(f"## {b01['label']}\n")
        out.append("| participant | median ms | mean ± σ ms | min…max ms | p95 ms | CV% | runs ok |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for key, p in b01["participants"].items():
            s = (p.get("summary") or {}).get("cold_first_response_ms", {})
            ok = s.get("n", 0) if s else 0
            fails = p.get("failures")
            nfail = len(fails) if isinstance(fails, list) else (fails or 0)
            out.append(f"| {NAMES.get(key, key)} | {fmt(s.get('median'))} | "
                       f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | {fmt(s.get('p95'))} | "
                       f"{fmt(s.get('cv_pct'))}{cv_flag(s)} | {ok}/{(ok or 0) + (nfail or 0)} |")
        out.append("")

    b03 = load("b03_rss_idle.json")
    if b03:
        out.append(f"## {b03['label']}\n")
        out.append("| participant | RSS median MiB | RSS max MiB | PSS median MiB | PSS max MiB |")
        out.append("| --- | --- | --- | --- | --- |")
        for key, p in b03["participants"].items():
            s = p.get("summary") or {}
            out.append(f"| {NAMES.get(key, key)} | {fmt(s.get('rss_mib_median'), 2)} | "
                       f"{fmt(s.get('rss_mib_max'), 2)} | {fmt(s.get('pss_mib_median'), 2)} | "
                       f"{fmt(s.get('pss_mib_max'), 2)} |")
        out.append("")

    b05 = load("b05_exec_latency.json")
    if b05:
        out.append(f"## {b05['label']}\n")
        out.append("| participant | p50 ms | p95 ms | p99 ms | mean ± σ ms | min…max ms | CV% |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for key, p in b05["participants"].items():
            s = p.get("summary") or {}
            out.append(f"| {NAMES.get(key, key)} | {fmt(s.get('p50'))} | {fmt(s.get('p95'))} | "
                       f"{fmt(s.get('p99'))} | {fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | {fmt(s.get('cv_pct'))}{cv_flag(s)} |")
        out.append("")

    b07 = load("b07_per_connection.json")
    if b07:
        out.append(f"## {b07['label']}\n")
        ours_raw = load("raw/b07_ours.json")
        if ours_raw:
            d = ours_raw.get("delta_rss_kib_per_connection")
            base = ours_raw.get("base_rss_kib")
            after = ours_raw.get("rss_kib_after_close")
            rec = ours_raw.get("recovered_delta_kib")
            recovery = "returned to base" if ours_raw.get("recovered") else f"still +{fmt(rec, 0)} KiB above base"
            out.append(f"- mcp-node-zig: base RSS {fmt(base, 0)} KiB; "
                       f"ΔRSS per connection ≈ {fmt(d, 1)} KiB over {ours_raw.get('connections_total')} connections; "
                       f"after closing all: {fmt(after, 0)} KiB ({recovery})")
        for key in ("tumf", "g0t4"):
            raw = load(f"raw/b07_{key}.json")
            if raw:
                out.append(f"- {NAMES.get(key, key)}: second agent = second process, "
                           f"{fmt(raw.get('second_agent_cost_kib'), 0)} KiB tree RSS")
        out.append("")

    b08 = load("b08_footprint.json")
    if b08:
        out.append("## delivery footprint\n")
        out.append("| participant | artifact | env MiB | runtime MiB |")
        out.append("| --- | --- | --- | --- |")
        o = b08.get("ours", {})
        out.append(f"| mcp-node-zig | one binary {fmt(o.get('binary_mib'), 2)} MiB | 0 | 0 |")
        t = b08.get("tumf", {})
        if t.get("venv_mib") is not None:
            out.append(f"| {t.get('participant')} | venv {fmt(t.get('venv_mib'))} MiB | "
                       f"{fmt((t.get('venv_mib') or 0) + (t.get('uv_cache_mib') or 0))} (venv + uv cache) | "
                       f"{fmt(t.get('runtime_mib'))} |")
        g = b08.get("g0t4", {})
        if g.get("package_env_mib") is not None:
            out.append(f"| {g.get('participant')} | npx env {fmt(g.get('package_env_mib'))} MiB | "
                       f"{fmt(g.get('package_env_mib'))} | {fmt(g.get('runtime_mib'))} |")
        out.append("")

    env = load("env.json")
    if env:
        cpu = env.get("cpu", {})
        out.append(f"stand: {env.get('hostname')} — {cpu.get('model')}, {cpu.get('cores')} cores, "
                   f"governor {cpu.get('governor')}; kernel {env.get('os', {}).get('kernel')}; "
                   f"{env.get('date_utc')}")
        out.append("")

    print("\n".join(out))


if __name__ == "__main__":
    main()
