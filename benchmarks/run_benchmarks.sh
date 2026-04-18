#!/usr/bin/env bash
# ============================================================================
#  Pyscan Reproducible Benchmarking Script
# ============================================================================
#  Idempotent: safe to re-run; overwrites previous results in the output dir.
#
#  What it does:
#    1. Validates all required tools are installed
#    2. Collects machine profile (CPU, RAM, OS, kernel)
#    3. Measures network latency (DNS + HTTPS to osv.dev API)
#    4. Runs hyperfine benchmarks: pyscan vs pip-audit (small/medium/large)
#    5. Profiles peak memory usage via /usr/bin/time -v
#    6. Assembles everything into a single JSON report
#
#  Usage:
#    chmod +x benchmarks/run_benchmarks.sh
#    ./benchmarks/run_benchmarks.sh                  # default: 5 runs, 3 warmups
#    BENCH_RUNS=10 BENCH_WARMUP=5 ./benchmarks/run_benchmarks.sh
# ============================================================================

set -euo pipefail

# ── Configurable Knobs ───────────────────────────────────────────────────────
RUNS="${BENCH_RUNS:-5}"
WARMUP="${BENCH_WARMUP:-3}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/results"
REPORT_FILE="$OUTPUT_DIR/benchmark_report.json"

# Dataset paths
DATASETS=(
  "small:$SCRIPT_DIR/small.txt"
  "medium:$SCRIPT_DIR/medium.txt"
  "large:$SCRIPT_DIR/large.txt"
)

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[  OK]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
header(){ echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

# ── Cleanup Trap ─────────────────────────────────────────────────────────────
# Pyscan discovers requirements.txt by filename inside a directory (-d flag).
# We create temp dirs with the dataset symlinked as "requirements.txt".
TEMP_DIRS=()
cleanup() {
  for d in "${TEMP_DIRS[@]}"; do
    rm -rf "$d" 2>/dev/null || true
  done
}
trap cleanup EXIT

# Creates a temp dir with dataset symlinked as requirements.txt.
# Prints the temp dir path.
make_pyscan_dir() {
  local src="$1"
  local tmpdir
  tmpdir=$(mktemp -d "/tmp/pyscan_bench.XXXXXX")
  ln -sf "$src" "$tmpdir/requirements.txt"
  TEMP_DIRS+=("$tmpdir")
  echo "$tmpdir"
}

# ── Preflight Checks ────────────────────────────────────────────────────────
header "🔍 Preflight Checks"

REQUIRED_TOOLS=(hyperfine pyscan pip-audit jq curl)
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    fail "'$tool' is not installed or not in PATH."
  fi
  ok "$tool  ✓"
done

# Check for /usr/bin/time (GNU time, NOT the shell built-in) — optional
HAS_GNU_TIME=false
if [[ -x /usr/bin/time ]]; then
  HAS_GNU_TIME=true
  ok "/usr/bin/time  ✓"
else
  warn "/usr/bin/time not found — memory profiling will be skipped."
  warn "  Install with: sudo pacman -S time"
fi

# Verify datasets exist
for entry in "${DATASETS[@]}"; do
  label="${entry%%:*}"
  path="${entry#*:}"
  if [[ ! -f "$path" ]]; then
    fail "Dataset '$label' not found at: $path"
  fi
  dep_count=$(wc -l < "$path" | tr -d ' ')
  ok "Dataset '$label' ($dep_count deps)  ✓"
done

# ── Prepare Output Directory (idempotent) ────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
info "Results will be written to: $OUTPUT_DIR/"

# ── Step 1: Machine Profile ─────────────────────────────────────────────────
header "🖥️  Collecting Machine Profile"

CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
CPU_CORES_PHYSICAL=$(grep -c '^processor' /proc/cpuinfo)
CPU_CORES_LOGICAL=$(nproc)
RAM_TOTAL=$(free -h | awk '/^Mem:/{print $2}')
RAM_AVAILABLE=$(free -h | awk '/^Mem:/{print $7}')
KERNEL=$(uname -r)
OS_PRETTY=$(grep -m1 'PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)
ARCH=$(uname -m)
PYSCAN_VERSION=$(pyscan --version 2>&1 | head -1)
PIP_AUDIT_VERSION=$(pip-audit --version 2>&1 | head -1)
HYPERFINE_VERSION=$(hyperfine --version 2>&1 | head -1)

MACHINE_JSON=$(jq -n \
  --arg cpu_model   "$CPU_MODEL" \
  --arg cpu_phys    "$CPU_CORES_PHYSICAL" \
  --arg cpu_logic   "$CPU_CORES_LOGICAL" \
  --arg ram_total   "$RAM_TOTAL" \
  --arg ram_avail   "$RAM_AVAILABLE" \
  --arg kernel      "$KERNEL" \
  --arg os          "$OS_PRETTY" \
  --arg arch        "$ARCH" \
  --arg pyscan_v    "$PYSCAN_VERSION" \
  --arg pipaudit_v  "$PIP_AUDIT_VERSION" \
  --arg hyperfine_v "$HYPERFINE_VERSION" \
  '{
    cpu_model:           $cpu_model,
    cpu_cores_physical:  ($cpu_phys | tonumber),
    cpu_cores_logical:   ($cpu_logic | tonumber),
    ram_total:           $ram_total,
    ram_available:       $ram_avail,
    kernel:              $kernel,
    os:                  $os,
    architecture:        $arch,
    tool_versions: {
      pyscan:     $pyscan_v,
      pip_audit:  $pipaudit_v,
      hyperfine:  $hyperfine_v
    }
  }')

ok "Machine profile collected"
echo "$MACHINE_JSON" | jq .

# ── Step 2: Network Measurement ─────────────────────────────────────────────
header "🌐 Measuring Network Conditions"

# DNS + HTTPS latency to the OSV API (the endpoint pyscan actually hits)
OSV_URL="https://api.osv.dev/v1/query"
NETWORK_SAMPLES=5
latencies=()

for i in $(seq 1 $NETWORK_SAMPLES); do
  # time_total includes DNS + TCP + TLS + HTTP round-trip
  ms=$(curl -so /dev/null -w '%{time_total}' \
       -X POST "$OSV_URL" \
       -H "Content-Type: application/json" \
       -d '{"package":{"name":"requests","ecosystem":"PyPI"},"version":"2.31.0"}' \
       2>/dev/null)
  # Convert seconds → milliseconds
  ms_val=$(awk "BEGIN {printf \"%.1f\", $ms * 1000}")
  latencies+=("$ms_val")
  info "  Sample $i: ${ms_val}ms"
done

# Compute average and stddev
LATENCY_AVG=$(printf '%s\n' "${latencies[@]}" | awk '{sum+=$1} END {printf "%.1f", sum/NR}')
LATENCY_STDDEV=$(printf '%s\n' "${latencies[@]}" | awk -v avg="$LATENCY_AVG" \
  '{d=$1-avg; sumsq+=d*d} END {printf "%.1f", sqrt(sumsq/NR)}')

# Measure download throughput (10MB test file from Cloudflare)
info "Measuring download throughput..."
DL_SPEED=$(curl -so /dev/null -w '%{speed_download}' \
  "https://speed.cloudflare.com/__down?bytes=10000000" 2>/dev/null)
DL_SPEED_MBPS=$(awk "BEGIN {printf \"%.2f\", $DL_SPEED * 8 / 1000000}")

NETWORK_JSON=$(jq -n \
  --arg osv_avg    "$LATENCY_AVG" \
  --arg osv_std    "$LATENCY_STDDEV" \
  --arg dl_mbps    "$DL_SPEED_MBPS" \
  --arg samples    "$NETWORK_SAMPLES" \
  '{
    osv_api_latency_ms: {
      mean:    ($osv_avg | tonumber),
      stddev:  ($osv_std | tonumber),
      samples: ($samples | tonumber)
    },
    download_speed_mbps: ($dl_mbps | tonumber)
  }')

ok "Network: OSV API ${LATENCY_AVG}ms ± ${LATENCY_STDDEV}ms, Download ${DL_SPEED_MBPS} Mbps"

# ── Step 3: Hyperfine Benchmarks ────────────────────────────────────────────
header "⚡ Running Hyperfine Benchmarks (runs=$RUNS, warmup=$WARMUP)"

BENCHMARKS_JSON="[]"

for entry in "${DATASETS[@]}"; do
  label="${entry%%:*}"
  path="${entry#*:}"
  dep_count=$(wc -l < "$path" | tr -d ' ')
  json_out="$OUTPUT_DIR/hyperfine_${label}.json"

  # pyscan needs a directory containing a requirements.txt
  pyscan_dir=$(make_pyscan_dir "$path")

  info "Benchmarking '$label' dataset ($dep_count deps)..."

  # --ignore-failure: both tools exit 1 when vulnerabilities are found (expected)
  hyperfine \
    --warmup "$WARMUP" \
    --runs "$RUNS" \
    --ignore-failure \
    --export-json "$json_out" \
    --command-name "pyscan ($label)" \
    "pyscan -d '$pyscan_dir'" \
    --command-name "pip-audit ($label)" \
    "pip-audit -r '$path' --progress-spinner off" \
    2>&1 | tee "$OUTPUT_DIR/hyperfine_${label}.log"

  # Extract hyperfine results and add dep_count metadata
  RESULT=$(jq --arg label "$label" --arg deps "$dep_count" \
    '{
      dataset: $label,
      dependency_count: ($deps | tonumber),
      results: .results | map({
        command:    .command,
        mean_s:     .mean,
        stddev_s:   .stddev,
        median_s:   .median,
        min_s:      .min,
        max_s:      .max,
        times:      .times
      })
    }' "$json_out")

  BENCHMARKS_JSON=$(echo "$BENCHMARKS_JSON" | jq --argjson r "$RESULT" '. + [$r]')
  ok "'$label' benchmark complete"
done

# ── Step 4: Memory Profiling ────────────────────────────────────────────────
header "🧠 Profiling Peak Memory Usage"

MEMORY_JSON="[]"

if [[ "$HAS_GNU_TIME" == "true" ]]; then
  for entry in "${DATASETS[@]}"; do
    label="${entry%%:*}"
    path="${entry#*:}"

    pyscan_dir=$(make_pyscan_dir "$path")

    info "Memory profile: pyscan ($label)..."
    pyscan_mem_out="$OUTPUT_DIR/mem_pyscan_${label}.txt"
    /usr/bin/time -v pyscan -d "$pyscan_dir" \
      >"$OUTPUT_DIR/mem_pyscan_${label}_stdout.txt" 2>"$pyscan_mem_out" || true
    PYSCAN_RSS=$(grep 'Maximum resident set size' "$pyscan_mem_out" | awk '{print $NF}')

    info "Memory profile: pip-audit ($label)..."
    pipaudit_mem_out="$OUTPUT_DIR/mem_pipaudit_${label}.txt"
    /usr/bin/time -v pip-audit -r "$path" --progress-spinner off \
      >"$OUTPUT_DIR/mem_pipaudit_${label}_stdout.txt" 2>"$pipaudit_mem_out" || true
    PIPAUDIT_RSS=$(grep 'Maximum resident set size' "$pipaudit_mem_out" | awk '{print $NF}')

    MEM_ENTRY=$(jq -n \
      --arg label      "$label" \
      --arg pyscan_kb  "${PYSCAN_RSS:-0}" \
      --arg pipaudit_kb "${PIPAUDIT_RSS:-0}" \
      '{
        dataset: $label,
        pyscan_peak_rss_kb:    ($pyscan_kb | tonumber),
        pip_audit_peak_rss_kb: ($pipaudit_kb | tonumber),
        pyscan_peak_rss_mb:    (($pyscan_kb | tonumber) / 1024 | round),
        pip_audit_peak_rss_mb: (($pipaudit_kb | tonumber) / 1024 | round)
      }')

    MEMORY_JSON=$(echo "$MEMORY_JSON" | jq --argjson e "$MEM_ENTRY" '. + [$e]')
    ok "Memory ($label): pyscan=${PYSCAN_RSS:-?}KB, pip-audit=${PIPAUDIT_RSS:-?}KB"
  done
else
  warn "Skipping memory profiling (/usr/bin/time not available)"
  MEMORY_JSON="null"
fi

# ── Step 5: Compute Derived Metrics ─────────────────────────────────────────
header "📊 Computing Speedup Ratios"

SUMMARY_JSON=$(echo "$BENCHMARKS_JSON" | jq '
  map({
    dataset: .dataset,
    dependency_count: .dependency_count,
    pyscan_mean_s:    (.results[] | select(.command | test("pyscan")) | .mean_s),
    pip_audit_mean_s: (.results[] | select(.command | test("pip-audit")) | .mean_s),
    pyscan_stddev_s:  (.results[] | select(.command | test("pyscan")) | .stddev_s),
    pip_audit_stddev_s: (.results[] | select(.command | test("pip-audit")) | .stddev_s),
    speedup_factor:   (
      (.results[] | select(.command | test("pip-audit")) | .mean_s) /
      (.results[] | select(.command | test("pyscan")) | .mean_s)
      | . * 100 | round / 100
    ),
    stability: (
      if ((.results[] | select(.command | test("pyscan")) | .stddev_s) /
          (.results[] | select(.command | test("pyscan")) | .mean_s)) < 0.1
      then "high"
      elif ((.results[] | select(.command | test("pyscan")) | .stddev_s) /
           (.results[] | select(.command | test("pyscan")) | .mean_s)) < 0.25
      then "moderate"
      else "low"
      end
    )
  })
')

echo "$SUMMARY_JSON" | jq .

# ── Step 6: Assemble Final JSON Report ──────────────────────────────────────
header "📝 Assembling Final Report"

FINAL_REPORT=$(jq -n \
  --arg ts          "$TIMESTAMP" \
  --arg runs        "$RUNS" \
  --arg warmup      "$WARMUP" \
  --argjson machine "$MACHINE_JSON" \
  --argjson network "$NETWORK_JSON" \
  --argjson bench   "$BENCHMARKS_JSON" \
  --argjson memory  "$MEMORY_JSON" \
  --argjson summary "$SUMMARY_JSON" \
  '{
    meta: {
      generated_at:  $ts,
      hyperfine_runs: ($runs | tonumber),
      warmup_runs:    ($warmup | tonumber),
      script:         "benchmarks/run_benchmarks.sh"
    },
    machine_profile: $machine,
    network:         $network,
    comparative_summary: $summary,
    benchmarks:      $bench,
    memory_profile:  $memory
  }')

echo "$FINAL_REPORT" | jq . > "$REPORT_FILE"

ok "Report saved to: $REPORT_FILE"
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✅  Benchmarking Complete!                       ${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Report:    ${CYAN}$REPORT_FILE${NC}"
echo -e "  Size:      $(du -h "$REPORT_FILE" | cut -f1)"
echo ""

# Print a quick summary table
echo -e "${BOLD}  Quick Summary:${NC}"
echo "$SUMMARY_JSON" | jq -r '
  .[] | "  \(.dataset | ascii_upcase)  │  pyscan: \(.pyscan_mean_s | . * 1000 | round / 1000)s  │  pip-audit: \(.pip_audit_mean_s | . * 1000 | round / 1000)s  │  \(.speedup_factor)x faster  │  stability: \(.stability)"
'
echo ""
