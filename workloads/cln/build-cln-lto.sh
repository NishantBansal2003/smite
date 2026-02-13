#!/bin/bash
#
# Build CLN with afl-clang-lto and per-binary AFL_LLVM_LTO_STARTID offsets.
#
# CLN spawns ~30 processes sharing one AFL bitmap. If we don't manually set
# AFL_LLVM_LTO_STARTID offsets, the coverage signal written by each process ends
# up colliding with signal written by other processes. By manually setting
# offsets, we ensure each process gets a unique region in the bitmap to write
# its coverage data, so we can fuzz with maximum coverage signal.
#
# This script:
# 1. Builds everything (objects as LLVM bitcode, initial link at STARTID=0)
# 2. Re-links each instrumented binary with a unique STARTID offset
# 3. Writes total map size to /tmp/total-map-size
# 4. Installs the properly-offset binaries

set -eu

echo "=== Pass 1: Initial build and install ==="
make -j"$(nproc)" install

echo "=== Pass 2: Re-linking with offsets ==="
OFFSET=0
for bin in lightningd/lightningd lightningd/lightning_* plugins/*; do
    # Skip non-ELF files (e.g., Python plugins) and non-instrumented binaries.
    if ! readelf -s "$bin" 2>/dev/null | grep -q '__afl_final_loc'; then
        continue
    fi

    rm "$bin"
    AFL_LLVM_LTO_STARTID=$OFFSET make -j"$(nproc)" "$bin"

    # AFL_DUMP_MAP_SIZE causes the binary to print its map size and exit(-1).
    MAP_SIZE=$(AFL_DUMP_MAP_SIZE=1 "$bin" 2>/dev/null) || true
    if [ -z "$MAP_SIZE" ]; then
        echo "ERROR: failed to get map size for $bin" >&2
        exit 1
    fi

    # AFL_DUMP_MAP_SIZE output already includes the STARTID offset, so it can be
    # used directly as the next binary's STARTID.
    echo "  $bin: offset=$OFFSET map_size=$MAP_SIZE"
    OFFSET=$MAP_SIZE
done

echo "=== Total map size: $OFFSET ==="
echo "$OFFSET" > /tmp/total-map-size

echo "=== Installing ==="
make install
