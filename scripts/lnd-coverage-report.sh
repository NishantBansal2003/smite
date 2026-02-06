#!/bin/bash
#
# Generate an HTML coverage report for LND from a corpus of fuzz inputs.
#
# Usage: ./scripts/lnd-coverage-report.sh <corpus-dir> [output-dir]
#
# This script:
# 1. Builds (if needed) a coverage-instrumented Docker image
# 2. Runs each corpus input through lnd-scenario
# 3. Merges coverage data and generates an HTML report
#
set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 <corpus-dir> [output-dir]"
    echo ""
    echo "Arguments:"
    echo "  corpus-dir  Directory containing fuzz input files"
    echo "  output-dir  Output directory for coverage report (default: ./coverage-report)"
    echo ""
    echo "Environment variables:"
    echo "  REBUILD=1   Force rebuild of Docker image"
    echo "  PARALLEL=N  Number of parallel jobs (default: number of CPU cores)"
    exit 1
fi

# Convert to absolute paths to prevent Docker from interpreting relative paths
# as named volumes
CORPUS_DIR="$(cd "$1" && pwd)"
OUTPUT_DIR="${2:-./coverage-report}"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

# Validate PARALLEL
MAX_JOBS="${PARALLEL:-$(nproc)}"
if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]] || [ "$MAX_JOBS" -eq 0 ]; then
    echo "Error: PARALLEL must be a positive integer, got '$MAX_JOBS'"
    exit 1
fi

# Verify corpus directory exists
if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: Corpus directory '$CORPUS_DIR' does not exist"
    exit 1
fi

# Count inputs
INPUT_COUNT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | wc -l)
if [ "$INPUT_COUNT" -eq 0 ]; then
    echo "Error: No input files found in '$CORPUS_DIR'"
    exit 1
fi

echo "Found $INPUT_COUNT input files in corpus"

# Build coverage image if needed (use REBUILD=1 to force rebuild)
if [ "${REBUILD:-}" = "1" ] || ! docker image inspect smite-lnd-coverage >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SMITE_DIR="$(dirname "$SCRIPT_DIR")"

    echo "Building coverage Docker image..."
    docker build -t smite-lnd-coverage -f "$SMITE_DIR/workloads/lnd/Dockerfile.coverage" "$SMITE_DIR"
fi

# Create output directories (remove old data to avoid mixing with previous runs)
rm -rf "$OUTPUT_DIR/covdata" "$OUTPUT_DIR/merged"
mkdir -p "$OUTPUT_DIR/covdata" "$OUTPUT_DIR/merged"

# Minimum expected coverage file size, set after running first input.
# Go's coverage runtime writes metadata first, then counters. Under high
# parallel load, processes may exit before counters are flushed, producing
# truncated files (~5KB smaller). We use this cutoff value to detect truncated
# files.
MIN_COV_SIZE=0

# Runs a single corpus input through the LND scenario.
#
# Note: We mount the entire corpus directory because AFL++ filenames contain
# colons (e.g., id:000000,time:0) which conflict with Docker's -v syntax. Also
# each input gets its own coverage subdirectory to avoid filename collisions.
run_input() {
    local i="$1"
    local input_name="$2"
    local covdir="$OUTPUT_DIR/covdata/input-$i"
    local max_retries=3

    for ((attempt=0; attempt<max_retries; attempt++)); do
        rm -rf "$covdir"
        mkdir "$covdir"

        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$CORPUS_DIR:/corpus:ro" \
            -v "$covdir:/covdata" \
            -e SMITE_INPUT="/corpus/$input_name" \
            -e GOCOVERDIR=/covdata \
            smite-lnd-coverage \
            /lnd-scenario >/dev/null 2>&1 || true

        # Verify coverage file size meets minimum threshold
        local covfile=$(ls "$covdir"/covcounters.* 2>/dev/null | head -1)
        if [ -f "$covfile" ]; then
            local size=$(stat -c%s "$covfile" 2>/dev/null || echo 0)
            if [ "$size" -ge "$MIN_COV_SIZE" ]; then
                return 0
            fi
        fi

        # Retry with backoff
        sleep $((attempt + 1))
    done

    echo "Warning: input-$i ($input_name) coverage may be incomplete after $max_retries attempts" >&2
}

# Run first input serially to establish coverage file size baseline.
echo "Running first input to establish coverage baseline..."
FIRST_INPUT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | head -1)
if [ -z "$FIRST_INPUT" ]; then
    echo "Error: No input files found"
    exit 1
fi
FIRST_NAME=$(basename "$FIRST_INPUT")
run_input 0 "$FIRST_NAME"

# Set the minimum coverage cutoff to 1000 bytes less than baseline coverage
BASELINE_FILE=$(ls "$OUTPUT_DIR/covdata/input-0"/covcounters.* 2>/dev/null | head -1)
if [ -z "$BASELINE_FILE" ]; then
    echo "Error: First input produced no coverage data"
    exit 1
fi
BASELINE_SIZE=$(stat -c%s "$BASELINE_FILE")
MIN_COV_SIZE=$((BASELINE_SIZE - 1000))
echo "Baseline coverage file size: $BASELINE_SIZE bytes (min threshold: $MIN_COV_SIZE)"

echo "Processing remaining $((INPUT_COUNT - 1)) inputs with $MAX_JOBS parallel jobs..."

# Process remaining inputs in parallel with job limiting
i=1
active_jobs=0
for input in "$CORPUS_DIR"/*; do
    [ -f "$input" ] || continue
    INPUT_NAME=$(basename "$input")

    # Skip first input (already processed)
    if [ "$INPUT_NAME" = "$FIRST_NAME" ]; then
        continue
    fi

    # Run in background
    run_input "$i" "$INPUT_NAME" &
    active_jobs=$((active_jobs + 1))
    i=$((i + 1))

    # Limit parallelism
    if [ "$active_jobs" -ge "$MAX_JOBS" ]; then
        echo "Progress: $i/$INPUT_COUNT inputs started"
        wait -n 2>/dev/null || true
        active_jobs=$((active_jobs - 1))
    fi
done

# Wait for remaining jobs
echo "Waiting for remaining jobs to complete..."
wait

echo ""
echo "Merging coverage data and generating report..."

# Merge coverage and generate report
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$OUTPUT_DIR:/output" \
    -e GOCACHE=/tmp/go-cache \
    -e GOPATH=/tmp/go \
    smite-lnd-coverage \
    sh -c '
        set -eu

        # Build comma-separated list of coverage directories
        COVDIRS=$(find /output/covdata -mindepth 1 -maxdepth 1 -type d | sort | tr "\n" "," | sed "s/,$//")
        if [ -z "$COVDIRS" ]; then
            echo "Error: No coverage data found"
            exit 1
        fi

        echo "Merging coverage data from $(echo "$COVDIRS" | tr "," "\n" | wc -l) directories..."
        go tool covdata merge -i="$COVDIRS" -o=/output/merged

        echo "Converting to text profile..."
        go tool covdata textfmt -i=/output/merged -o=/output/coverage.txt

        echo "Generating HTML report..."
        cd /lnd && go tool cover -html=/output/coverage.txt -o=/output/coverage.html

        echo ""
        echo "Coverage summary:"
        go tool covdata percent -i=/output/merged
    '

echo ""
echo "Coverage report generated: $OUTPUT_DIR/coverage.html"
