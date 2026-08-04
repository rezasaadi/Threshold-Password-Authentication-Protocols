#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean

PAIR_ORDER = [(3, 2), (6, 3), (10, 5), (10, 10)]


def fms(ns: float | None) -> str:
    return "--" if ns is None else f"{ns / 1_000_000:.3f}"


def latex_escape(s: str) -> str:
    return s.replace("_", r"\_")


def parse_modern(path: Path) -> list[dict]:
    rows: list[dict] = []
    lines = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not lines:
        return rows
    header = lines[0].split()
    if "scheme" not in header or "kind" not in header:
        return rows
    file_pair = re.search(r"exp1_modern_(\d+)_(\d+)_run\d+\.dat$", path.name)
    for line in lines[1:]:
        vals = line.split()
        if len(vals) != len(header):
            continue
        d = dict(zip(header, vals))
        try:
            n = int(d["nsp"])
            t = int(d["tsp"])
            # The supplied modern runner labels constant-cost PartEval/Verify
            # rows as (0,0). Each exp1 process contains exactly one requested
            # pair, so retain that pair for the comparison table.
            if n == 0 and t == 0 and d["op"] in {"ttg_part_eval", "ttg_verify"} and file_pair:
                n, t = map(int, file_pair.groups())
            rows.append({
                "profile": "modern",
                "experiment": "exp1" if d["kind"] in {"prim", "proto", "sp"} else "modeled",
                "metric": d["op"],
                "network": "",
                "n": n,
                "t": t,
                "samples": int(d["samples"]),
                "warmup": int(d["warmup"]),
                "min_ns": float(d["min_ns"]),
                "p50_ns": float(d["p50_ns"]),
                "p95_ns": float(d["p95_ns"]),
                "max_ns": float(d["max_ns"]),
                "mean_ns": float(d["mean_ns"]),
                "stddev_ns": float(d["stddev_ns"]),
                "source": str(path),
            })
        except (KeyError, ValueError):
            continue
    return rows


def parse_canonical(path: Path) -> list[dict]:
    rows: list[dict] = []
    lines = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not lines:
        return rows
    header = lines[0].split()
    required = {"profile", "experiment", "metric", "n", "t", "mean_ns"}
    if not required.issubset(header):
        return rows
    for line in lines[1:]:
        vals = line.split()
        if len(vals) != len(header):
            continue
        d = dict(zip(header, vals))
        try:
            rows.append({
                "profile": d["profile"],
                "experiment": d["experiment"],
                "metric": d["metric"],
                "network": d.get("network", ""),
                "n": int(d["n"]),
                "t": int(d["t"]),
                "samples": int(d.get("samples", 0)),
                "warmup": int(d.get("warmup", 0)),
                "min_ns": float(d.get("min_ns", "nan")),
                "p50_ns": float(d.get("p50_ns", "nan")),
                "p95_ns": float(d.get("p95_ns", "nan")),
                "max_ns": float(d.get("max_ns", "nan")),
                "mean_ns": float(d["mean_ns"]),
                "stddev_ns": float(d.get("stddev_ns", "nan")),
                "source": str(path),
            })
        except (KeyError, ValueError):
            continue
    return rows


def collect(raw: Path) -> list[dict]:
    all_rows: list[dict] = []
    for path in sorted(raw.glob("*.dat")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if text.startswith("scheme kind op"):
            all_rows.extend(parse_modern(path))
        else:
            all_rows.extend(parse_canonical(path))
    return all_rows


def agg(rows: list[dict]) -> dict[tuple, dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        key = (r["profile"], r["experiment"], r["metric"], r["network"], r["n"], r["t"])
        groups[key].append(r)
    out: dict[tuple, dict] = {}
    for key, rs in groups.items():
        out[key] = {
            "mean_ns": mean(r["mean_ns"] for r in rs),
            "p50_ns": mean(r["p50_ns"] for r in rs if not math.isnan(r["p50_ns"])),
            "p95_ns": mean(r["p95_ns"] for r in rs if not math.isnan(r["p95_ns"])),
            "runs": len(rs),
        }
    return out


def lookup(a: dict, profile: str, experiment: str, metric: str, n: int, t: int, network: str = "") -> dict | None:
    return a.get((profile, experiment, metric, network, n, t))


def first_metric(a: dict, candidates: list[tuple[str, str, str, str]], n: int, t: int) -> dict | None:
    for profile, exp, metric, network in candidates:
        v = lookup(a, profile, exp, metric, n, t, network)
        if v is not None:
            return v
    return None


def write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def table_ttg(a: dict, processed: Path, tables: Path) -> None:
    csv_rows = []
    tex = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Isolated TTG costs for the modern and paper-style Rust PAS-TA-U profiles. Times are arithmetic means in milliseconds.}",
        r"\label{tab:pastau-ttg-profiles}",
        r"\begin{tabular}{c l l r r r}",
        r"\toprule",
        r"$(t,n)$ & Implementation & TTG & PartEval/SP & Combine/client & Verify \\",
        r"\midrule",
    ]
    profiles = [
        ("modern", "Modern Rust PAS-TA-U", "BLS12-381"),
        ("paper_style", "Paper-style Rust PAS-TA-U", "Shoup RSA-2048"),
    ]
    for n, t in PAIR_ORDER:
        for profile, label, ttg in profiles:
            exp = "exp1"
            p = lookup(a, profile, exp, "ttg_part_eval", n, t)
            c = lookup(a, profile, exp, "ttg_combine_t", n, t)
            v = lookup(a, profile, exp, "ttg_verify", n, t)
            csv_rows.append([t, n, label, ttg,
                             None if p is None else p["mean_ns"] / 1e6,
                             None if c is None else c["mean_ns"] / 1e6,
                             None if v is None else v["mean_ns"] / 1e6])
            tex.append(f"$({t},{n})$ & {label} & {ttg} & {fms(None if p is None else p['mean_ns'])} & {fms(None if c is None else c['mean_ns'])} & {fms(None if v is None else v['mean_ns'])} " + r"\\")
    tex.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\linewidth}\footnotesize",
        r"The published PAS-TA-U evaluation does not report isolated TTG PartEval, Combine, and Verify costs; it reports complete token-generation latency.",
        r"\end{minipage}",
        r"\end{table}",
    ])
    write_csv(processed / "ttg_profiles.csv", ["t", "n", "implementation", "ttg", "part_eval_ms", "combine_ms", "verify_ms"], csv_rows)
    (tables / "ttg_profiles.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def table_all_three(a: dict, cfg: dict, metric: str, processed: Path, tables: Path) -> None:
    is_update = metric == "password_update"
    title = "Password-update" if is_update else "Token-generation"
    label = "password-update" if is_update else "token-generation"
    csv_rows = []
    tex = [
        r"\begin{table}[t]",
        r"\centering",
        rf"\caption{{{title} comparison for the two Rust PAS-TA-U profiles and the published PAS-TA-U implementation. Rust e2e values are real TCP-socket measurements under Linux \texttt{{tc}}; published values use the original Python/OpenSSH environment.}}",
        rf"\label{{tab:pastau-{label}-all-three}}",
        r"\begin{tabular}{l c r r r}",
        r"\toprule",
        r"Network & $(t,n)$ & Modern Rust & Paper-style Rust & Published PAS-TA-U \\",
        r"\midrule",
    ]
    published = cfg["published"]["password_update" if is_update else "token_generation"]
    metric_name = "password_update_tcp" if is_update else "token_generation_tcp"
    for network in ["lan4", "wan80"]:
        for n, t in PAIR_ORDER:
            modern = lookup(a, "modern", "exp2", metric_name, n, t, network)
            paper = lookup(a, "paper_style", "exp2", metric_name, n, t, network)
            pub = published[network][f"{n},{t}"]
            mm = None if modern is None else modern["mean_ns"] / 1e6
            pm = None if paper is None else paper["mean_ns"] / 1e6
            csv_rows.append([network, t, n, mm, pm, pub])
            tex.append(f"{network.upper()} & $({t},{n})$ & {'--' if mm is None else f'{mm:.3f}'} & {'--' if pm is None else f'{pm:.3f}'} & {pub:.1f} " + r"\\")
        if network == "lan4":
            tex.append(r"\midrule")
    tex.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    stem = "password_update_all_three" if is_update else "token_generation_all_three"
    write_csv(processed / f"{stem}.csv", ["network", "t", "n", "modern_ms", "paper_style_ms", "published_ms"], csv_rows)
    (tables / f"{stem}.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def table_ssh(a: dict, cfg: dict, processed: Path, tables: Path) -> None:
    csv_rows = []
    tex = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Paper-style Rust PAS-TA-U through the OpenSSH agent interface. Signing-service time is the PAS-TA-U threshold-signing portion; handshake time is the complete SSH command latency.}",
        r"\label{tab:pastau-ssh-validation}",
        r"\begin{tabular}{l c r r r}",
        r"\toprule",
        r"Network & $(t,n)$ & Sign service & SSH handshake & Published token generation \\",
        r"\midrule",
    ]
    published = cfg["published"]["token_generation"]
    for network in ["lan4", "wan80"]:
        for n, t in PAIR_ORDER:
            sign = lookup(a, "paper_style", "exp3", "ssh_sign_service", n, t, network)
            hs = lookup(a, "paper_style", "exp3", "ssh_handshake", n, t, network)
            pub = published[network][f"{n},{t}"]
            sm = None if sign is None else sign["mean_ns"] / 1e6
            hm = None if hs is None else hs["mean_ns"] / 1e6
            csv_rows.append([network, t, n, sm, hm, pub])
            tex.append(f"{network.upper()} & $({t},{n})$ & {'--' if sm is None else f'{sm:.3f}'} & {'--' if hm is None else f'{hm:.3f}'} & {pub:.1f} " + r"\\")
        if network == "lan4":
            tex.append(r"\midrule")
    tex.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}"])
    write_csv(processed / "ssh_validation.csv", ["network", "t", "n", "sign_service_ms", "ssh_handshake_ms", "published_token_ms"], csv_rows)
    (tables / "ssh_validation.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    args = ap.parse_args()
    root = args.root.resolve()
    raw = root / "results" / "raw"
    processed = root / "results" / "processed"
    tables = root / "results" / "tables"
    processed.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    cfg = json.loads((root / "experiments" / "config.json").read_text(encoding="utf-8"))
    rows = collect(raw)
    a = agg(rows)
    table_ttg(a, processed, tables)
    table_all_three(a, cfg, "token_generation", processed, tables)
    table_all_three(a, cfg, "password_update", processed, tables)
    table_ssh(a, cfg, processed, tables)
    print(f"Parsed {len(rows)} raw rows")
    print(f"Wrote CSV files to {processed}")
    print(f"Wrote LaTeX tables to {tables}")


if __name__ == "__main__":
    main()
