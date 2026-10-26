#!/usr/bin/env python3
"""
Reduce multiple wan.csv runs into a single best-of-N composite CSV.
For throughput/goodput metrics: selects the maximum (best) value.
For latency, jitter, packet loss, and CPU utilization: selects the minimum (best) value.
"""
import csv
import sys
from pathlib import Path

def reduce_runs(csv_paths, output_path):
    all_runs = []
    for p in csv_paths:
        with open(p, "r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            if rows:
                all_runs.append(rows)

    if not all_runs:
        print("No valid CSV runs to reduce.")
        sys.exit(1)

    template = all_runs[0]
    best_rows = []

    for i, row in enumerate(template):
        key = (row["tunnel"], row["profile"], row["param"], row["metric"])

        values = []
        for run in all_runs:
            if i < len(run):
                r = run[i]
                if (r["tunnel"], r["profile"], r["param"], r["metric"]) == key:
                    try:
                        values.append(float(r["value"]))
                    except (ValueError, TypeError):
                        pass

        if not values:
            best_rows.append(row)
            continue

        metric = row["metric"]
        profile = row["profile"]

        if metric == "mbit_s":
            best_val = max(values)
            fmt_val = f"{best_val:.1f}"
        elif metric == "pct":
            if profile in ("loss_effective", "udp_loss", "cpu_used"):
                best_val = min(values)
            else:
                best_val = max(values)
            if profile == "loss_effective":
                fmt_val = f"{int(round(best_val))}"
            elif profile == "cpu_used":
                fmt_val = f"{best_val:.1f}"
            else:
                fmt_val = f"{best_val:.2f}"
        elif metric in ("ms", "rtt_ms"):
            best_val = min(values)
            fmt_val = f"{best_val:.3f}"
        else:
            best_val = max(values)
            fmt_val = str(best_val)

        new_row = dict(row)
        new_row["value"] = fmt_val
        best_rows.append(new_row)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["ts", "host_pair", "commit", "tunnel", "profile", "param", "metric", "value", "conditions"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(best_rows)

    print(f"Successfully reduced {len(all_runs)} runs into: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: reduce_best_of_3.py <output_csv> <input_csv_1> <input_csv_2> [input_csv_3...]")
        sys.exit(1)
    reduce_runs(sys.argv[2:], sys.argv[1])
