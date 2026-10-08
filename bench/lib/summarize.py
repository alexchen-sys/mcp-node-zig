#!/usr/bin/env python3
"""Render result tables from bench/results/*.json.

Two renderers over the same aggregates:
- default: the compact internal summary (results/summary.md shape)
- --benchmarks: the public BENCHMARKS.md tables block, emitted between
  <!-- bench:tables:start --> and <!-- bench:tables:end --> markers, so the
  document's tables regenerate from a results directory after every
  evidence run; --update PATH replaces the block inside that document.

Every number traces to the JSON aggregates; this is a renderer, not a
calculator. Raw per-sample JSONL lives in results/raw/.
"""
import argparse
import json
import os
import sys

NAMES = {"ours": "mcp-node-zig", "tumf": "tumf/mcp-shell-server",
         "g0t4": "g0t4/mcp-server-commands"}

TABLES_START = "<!-- bench:tables:start -->"
TABLES_END = "<!-- bench:tables:end -->"


def load(results, name):
    path = os.path.join(results, name)
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


def pp3(summary):
    """Compact p50/p90/p99 triple for a summarize dict."""
    if not summary or not summary.get("n"):
        return "-"
    return f"{fmt(summary.get('p50', summary.get('median')), 1)} / " \
           f"{fmt(summary.get('p90'), 1)} / {fmt(summary.get('p99'), 1)}"


def hist_line(summary, nd=1):
    """Non-empty log2 buckets as a compact shape line (or None)."""
    h = (summary or {}).get("histogram")
    if not h or not h.get("buckets"):
        return None
    parts = []
    for b in h["buckets"]:
        if b["count"]:
            parts.append(f"[{fmt(b['floor'], 0)}, {fmt(b['ceil'], 0)}) {b['count']}")
    return "; ".join(parts) if parts else None


def failures_of(p):
    fails = p.get("failures")
    if isinstance(fails, list):
        return len(fails)
    return fails or 0


# ------------------------------------------------------------------ env

def governor_of(env):
    cpu = (env or {}).get("cpu", {})
    gpp = cpu.get("governor_per_policy")
    if gpp:
        return "/".join(sorted(set(gpp.values())))
    return cpu.get("governor")


def freq_stats(env):
    f = (env or {}).get("cpu", {}).get("cpu_freq_mhz_observed")
    if not f:
        return None, None
    return round(min(f), 1), round(max(f), 1)


def env_paragraph(results, public=False):
    env = load(results, "env.json")
    if not env:
        return ["_(no env.json — run the suite)_"]
    env_end = load(results, "env_end.json")
    cpu = env.get("cpu", {})
    out = []
    gov_start = governor_of(env)
    freq_lo, freq_hi = freq_stats(env)
    gov_txt = gov_start if gov_start else (cpu.get("cpufreq_note") or "unknown")
    freq_txt = f", observed {freq_lo}-{freq_hi} MHz" if freq_lo is not None else ""
    if public:
        out.append(f"- Stand: {env.get('hostname')} — {cpu.get('model')}, "
                   f"{cpu.get('cores')} cores, governor {gov_txt}{freq_txt}; "
                   f"kernel {env.get('os', {}).get('kernel')}; "
                   f"binary sha256 {(env.get('binary') or {}).get('sha256')}; "
                   f"passports: {env.get('date_utc')}.")
        if cpu.get("cpufreq_note"):
            out.append(f"- cpufreq: {cpu['cpufreq_note']} (frequency/governor "
                       "reported, never changed).")
    else:
        out.append(f"stand: {env.get('hostname')} — {cpu.get('model')}, {cpu.get('cores')} cores, "
                   f"governor {gov_txt}{freq_txt}; kernel {env.get('os', {}).get('kernel')}; "
                   f"{env.get('date_utc')}")
    if env_end:
        gov_end = governor_of(env_end)
        end_lo, end_hi = freq_stats(env_end)
        drift = []
        if gov_start and gov_end and gov_start != gov_end:
            drift.append(f"governor changed: {gov_start} -> {gov_end}")
        if freq_lo is not None and end_lo is not None:
            drift.append(f"observed frequency range changed: {freq_lo}-{freq_hi} MHz "
                         f"-> {end_lo}-{end_hi} MHz")
        end_freq_txt = f", observed {end_lo}-{end_hi} MHz" if end_lo is not None else ""
        if public:
            out.append(f"- End of run: governor {gov_end or 'unknown'}{end_freq_txt}; "
                       f"start was governor {gov_start or 'unknown'}"
                       + (f", {freq_lo}-{freq_hi} MHz" if freq_lo is not None else "")
                       + (f" — DRIFT: {'; '.join(drift)}" if drift else " — no drift."))
        else:
            out.append(f"end of run: governor {gov_end or 'unknown'}{end_freq_txt} "
                       f"(start: {gov_start or 'unknown'}"
                       + (f", {freq_lo}-{freq_hi} MHz" if freq_lo is not None else "")
                       + (f"; DRIFT: {'; '.join(drift)} (!)" if drift else "") + ")")
    return out


# ------------------------------------------------------------- b01 (cold)

def b01_table(results, public):
    b01 = load(results, "b01_cold_start.json")
    if not b01:
        return [f"### Cold start → first MCP response (b01)", "_(no data)_"]
    out = ["### Cold start → first MCP response (b01)",
           f"_{b01['label']}_" if public else b01["label"]]
    if public:
        out.append("| participant | N ok | failures | p50 ms | p90 ms | p95 ms | p99 ms | "
                   "min…max ms | mean ± σ ms | CV% |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    else:
        out.append("| participant | median ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | "
                   "min…max ms | CV% | runs ok |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, p in b01["participants"].items():
        s = (p.get("summary") or {}).get("cold_first_response_ms", {})
        nfail = failures_of(p)
        name = NAMES.get(key, key)
        if public:
            out.append(f"| {name} | {s.get('n', 0)} | {nfail} | {fmt(s.get('p50', s.get('median')))} | "
                       f"{fmt(s.get('p90'))} | {fmt(s.get('p95'))} | {fmt(s.get('p99'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | "
                       f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('cv_pct'))}{cv_flag(s)} |")
        else:
            out.append(f"| {name} | {fmt(s.get('median'))} | {fmt(s.get('p90'))} | "
                       f"{fmt(s.get('p95'))} | {fmt(s.get('p99'))} | "
                       f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | "
                       f"{fmt(s.get('cv_pct'))}{cv_flag(s)} | {s.get('n', 0)}/{(s.get('n') or 0) + nfail} |")
    return out


def b01_decomposition_table(results):
    b01 = load(results, "b01_cold_start.json")
    if not b01:
        return []
    rows = []
    for key, p in b01["participants"].items():
        s = p.get("summary") or {}
        boot = s.get("boot_listen_ms") or {}
        init = s.get("initialize_handshake_ms") or {}
        if boot.get("n") or init.get("n"):
            rows.append(f"| {NAMES.get(key, key)} | {pp3(boot)} | {pp3(init)} | "
                        f"{fmt(boot.get('mean'))} + {fmt(init.get('mean'))} |")
    if not rows:
        return []
    return ["", "#### Cold-start decomposition (b01, http transport)",
            "| participant | boot→listen p50/p90/p99 ms | listen→initialize p50/p90/p99 ms | "
            "mean sum ms |",
            "| --- | --- | --- | --- |"] + rows + [
        "_stdio participants: spawn→first response is atomic over pipes, no "
        "decomposition (bundled in the table above)._"]


# ------------------------------------------------------------- b02 (TLS)

def b02_section(results, public):
    b02 = load(results, "b02_tls_handshake.json")
    if not b02:
        return ["### TLS node-link handshake (b02)", "_(no data)_"]
    out = ["### TLS node-link handshake (b02)"]
    if b02.get("skipped"):
        out.append(f"_skipped: {b02['skipped']}_")
        return out
    if b02.get("error"):
        out.append(f"_error: {b02['error']}_")
        return out
    c = b02.get("client", {})
    n = b02.get("node", {})
    cs = c.get("summary", {})
    ns = (n.get("summary") or {}).get("link_established_ms")
    out.append("| phase | N ok | failures | p50 ms | p90 ms | p99 ms | min…max ms | mean ± σ ms |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for label, key in (("TCP connect", "tcp_connect_ms"),
                       ("TLS 1.3 handshake", "tls_handshake_ms"),
                       ("total (connect+handshake)", "total_ms")):
        s = cs.get(key) or {}
        out.append(f"| {label} | {s.get('n', 0)} | {c.get('failures', 0)} | "
                   f"{fmt(s.get('p50', s.get('median')))} | {fmt(s.get('p90'))} | "
                   f"{fmt(s.get('p99'))} | {fmt(s.get('min'))}…{fmt(s.get('max'))} | "
                   f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} |")
    if ns:
        out.append(f"| node link established (spawn→registered) | {ns.get('n', 0)} | "
                   f"{n.get('failures', 0)} | {fmt(ns.get('p50'))} | {fmt(ns.get('p90'))} | "
                   f"{fmt(ns.get('p99'))} | {fmt(ns.get('min'))}…{fmt(ns.get('max'))} | "
                   f"{fmt(ns.get('mean'))} ± {fmt(ns.get('sigma'))} |")
    if c.get("tls_versions"):
        out.append(f"_negotiated: {json.dumps(c['tls_versions'], sort_keys=True)}; "
                   f"ciphers: {json.dumps(c.get('ciphers', {}), sort_keys=True)}_")
    hl = hist_line(cs.get("tls_handshake_ms"))
    if hl:
        out.append(f"_handshake histogram (ms, [floor, ceil) count): {hl}_")
    return out


# ------------------------------------------------------------- b03/b05/b07/b08

def b03_table(results, public):
    b03 = load(results, "b03_rss_idle.json")
    if not b03:
        return ["### Idle RSS (b03)", "_(no data)_"]
    out = ["### Idle RSS (b03)"]
    out.append("| participant | RSS median MiB | RSS max MiB | PSS median MiB | PSS max MiB |")
    out.append("| --- | --- | --- | --- | --- |")
    for key, p in b03["participants"].items():
        s = p.get("summary") or {}
        out.append(f"| {NAMES.get(key, key)} | {fmt(s.get('rss_mib_median'), 2)} | "
                   f"{fmt(s.get('rss_mib_max'), 2)} | {fmt(s.get('pss_mib_median'), 2)} | "
                   f"{fmt(s.get('pss_mib_max'), 2)} |")
    return out


def b05_table(results, public):
    b05 = load(results, "b05_exec_latency.json")
    if not b05:
        return ["### Exec round-trip latency (b05)", "_(no data)_"]
    out = ["### Exec round-trip latency (b05)"]
    if public:
        out.append("| participant | N ok | failures | p50 ms | p90 ms | p95 ms | p99 ms | "
                   "min…max ms | mean ± σ ms | CV% |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    else:
        out.append("| participant | p50 ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | "
                   "min…max ms | CV% |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, p in b05["participants"].items():
        s = p.get("summary") or {}
        name = NAMES.get(key, key)
        nfail = failures_of(p)
        if public:
            out.append(f"| {name} | {(s or {}).get('n', 0)} | {nfail} | {fmt(s.get('p50'))} | "
                       f"{fmt(s.get('p90'))} | {fmt(s.get('p95'))} | {fmt(s.get('p99'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | "
                       f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('cv_pct'))}{cv_flag(s)} |")
        else:
            out.append(f"| {name} | {fmt(s.get('p50'))} | {fmt(s.get('p90'))} | "
                       f"{fmt(s.get('p95'))} | {fmt(s.get('p99'))} | "
                       f"{fmt(s.get('mean'))} ± {fmt(s.get('sigma'))} | "
                       f"{fmt(s.get('min'))}…{fmt(s.get('max'))} | "
                       f"{fmt(s.get('cv_pct'))}{cv_flag(s)} |")
        hl = hist_line(s)
        if public and hl:
            out.append(f"| {name} histogram (ms) | | | | | | | "
                       f"{_hist_md(hl)} | | |")
    return out


def _hist_md(hl):
    return hl.replace("|", "/")


def b07_section(results, public):
    b07 = load(results, "b07_per_connection.json")
    if not b07:
        return ["### Per-agent memory (b07)", "_(no data)_"]
    out = ["### Memory per additional agent (b07)"]
    ours_raw = load(results, "raw/b07_ours.json")
    if ours_raw:
        d = ours_raw.get("delta_rss_kib_per_connection")
        base = ours_raw.get("base_rss_kib")
        after = ours_raw.get("rss_kib_after_close")
        rec = ours_raw.get("recovered_delta_kib")
        recovery = ("returned to base" if ours_raw.get("recovered")
                    else f"still +{fmt(rec, 0)} KiB above base")
        out.append(f"- mcp-node-zig: base RSS {fmt(base, 0)} KiB; "
                   f"ΔRSS per connection ≈ {fmt(d, 1)} KiB over "
                   f"{ours_raw.get('connections_total')} connections; "
                   f"after closing all: {fmt(after, 0)} KiB ({recovery})")
    for key in ("tumf", "g0t4"):
        raw = load(results, f"raw/b07_{key}.json")
        if raw:
            out.append(f"- {NAMES.get(key, key)}: second agent = second process, "
                       f"{fmt(raw.get('second_agent_cost_kib'), 0)} KiB tree RSS")
    return out


def b08_section(results, public):
    b08 = load(results, "b08_footprint.json")
    if not b08:
        return ["### Delivery footprint (b08)", "_(no data)_"]
    out = ["### Delivery footprint (b08)"]
    out.append("| participant | artifact | env MiB | runtime MiB |")
    out.append("| --- | --- | --- | --- |")
    o = b08.get("ours", {})
    out.append(f"| mcp-node-zig | one binary {fmt(o.get('binary_mib'), 2)} MiB | 0 | 0 |")
    t = b08.get("tumf", {})
    if t.get("venv_mib") is not None:
        out.append(f"| {t.get('participant')} | venv {fmt(t.get('venv_mib'))} MiB | "
                   f"{fmt((t.get('venv_mib') or 0) + (t.get('uv_cache_mib') or 0))} "
                   "(venv + uv cache) | "
                   f"{fmt(t.get('runtime_mib'))} |")
    g = b08.get("g0t4", {})
    if g.get("package_env_mib") is not None:
        out.append(f"| {g.get('participant')} | npx env {fmt(g.get('package_env_mib'))} MiB | "
                   f"{fmt(g.get('package_env_mib'))} | {fmt(g.get('runtime_mib'))} |")
    return out


# ------------------------------------------------------------- renderers

def render_summary(results):
    out = ["# bench results summary", ""]
    out += b01_table(results, public=False)
    out += b01_decomposition_table(results)
    out += b02_section(results, public=False)
    out += b03_table(results, public=False)
    out += b05_table(results, public=False)
    out += b07_section(results, public=False)
    out += b08_section(results, public=False)
    out += env_paragraph(results, public=False)
    return "\n".join(out) + "\n"


def render_benchmarks_block(results):
    out = [TABLES_START, ""]
    out += b01_table(results, public=True)
    out += b01_decomposition_table(results)
    out += [""]
    out += b02_section(results, public=True)
    out += [""]
    out += b05_table(results, public=True)
    out += [""]
    out += b03_table(results, public=True)
    out += [""]
    out += b07_section(results, public=True)
    out += [""]
    out += b08_section(results, public=True)
    out += ["", "### Environment", ""]
    out += env_paragraph(results, public=True)
    out += [TABLES_END]
    return "\n".join(out) + "\n"


def update_doc(path, block):
    with open(path) as f:
        doc = f.read()
    if TABLES_START not in doc or TABLES_END not in doc:
        sys.exit(f"{path}: no {TABLES_START} / {TABLES_END} markers to update")
    head = doc.split(TABLES_START)[0]
    tail = doc.split(TABLES_END)[1]
    new = head + block.rstrip("\n") + tail
    if not head.endswith("\n") and head:
        new = head + "\n" + block.rstrip("\n") + tail
    with open(path, "w") as f:
        f.write(new)
    print(f"updated tables in {path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("results", nargs="?",
                    default=os.path.join(os.path.dirname(__file__), "..", "results"),
                    help="results directory (aggregates + raw/)")
    ap.add_argument("--benchmarks", action="store_true",
                    help="render the BENCHMARKS.md tables block instead of the "
                         "internal summary")
    ap.add_argument("--update", default=None, metavar="BENCHMARKS.md",
                    help="with --benchmarks: replace the marked tables block "
                         "inside this document")
    args = ap.parse_args()

    results = args.results
    if not os.path.isdir(results):
        sys.exit(f"results directory not found: {results}")

    if args.benchmarks:
        block = render_benchmarks_block(results)
        if args.update:
            update_doc(args.update, block)
        else:
            print(block, end="")
    else:
        print(render_summary(results), end="")


if __name__ == "__main__":
    main()
