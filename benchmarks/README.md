# Benchmarks

Reproducible `pyscan` vs `pip-audit` performance comparison across three dataset sizes.

## Prerequisites

| Tool | Required | Install |
|---|---|---|
| `hyperfine` | ✅ | `pacman -S hyperfine` |
| `pyscan` | ✅ | `cargo install --path .` or `pipx install pyscan` |
| `pip-audit` | ✅ | `pipx install pip-audit` |
| `jq`, `curl` | ✅ | `pacman -S jq curl` |
| `/usr/bin/time` | optional | `pacman -S time` (enables memory profiling) |

## Usage

```bash
./benchmarks/run_benchmarks.sh
```

Override defaults with env vars:

```bash
BENCH_RUNS=10 BENCH_WARMUP=5 ./benchmarks/run_benchmarks.sh
```

## What It Does

1. **Preflight** — validates all tools exist
2. **Machine profile** — CPU, RAM, OS, kernel, tool versions
3. **Network** — OSV API latency (5 samples) + download throughput
4. **Hyperfine** — timed runs across `small.txt` (15 deps), `medium.txt` (88 deps), `large.txt` (714 deps)
5. **Memory** — peak RSS via `/usr/bin/time -v` (skipped if unavailable)
6. **Report** — assembles everything into a single JSON

## Datasets

| File | Deps | Purpose |
|---|---|---|
| `small.txt` | 15 | Baseline / cold-start measurement |
| `medium.txt` | 88 | Typical project |
| `large.txt` | 714 | Stress test (monolith-scale) |

## Output

All results land in `results/` (gitignored):

```
results/
├── benchmark_report.json    ← the single source of truth
├── hyperfine_small.json     ← raw hyperfine data
├── hyperfine_medium.json
├── hyperfine_large.json
└── mem_*.txt                ← raw /usr/bin/time output
```

The JSON report structure:

```jsonc
{
  "meta":                 { "generated_at", "hyperfine_runs", "warmup_runs" },
  "machine_profile":      { "cpu_model", "ram_total", "os", "tool_versions", ... },
  "network":              { "osv_api_latency_ms", "download_speed_mbps" },
  "comparative_summary":  [{ "dataset", "speedup_factor", "stability", ... }],
  "benchmarks":           [{ "dataset", "results": [{ "mean_s", "stddev_s", ... }] }],
  "memory_profile":       [{ "dataset", "pyscan_peak_rss_kb", ... }]  // or null
}
```

## Notes

- **Idempotent** — safe to re-run; overwrites previous results.
- pyscan needs a directory with a `requirements.txt` inside it. The script handles this by creating temp dirs with symlinks (cleaned up on exit).
- If `stddev > 10% of mean`, your environment was noisy — close background apps and retry.
