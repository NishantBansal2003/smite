#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the CLN fuzzing harness
export SMITE_NYX=1
export PATH=$PATH:/usr/local/bin

# Override the default crash handler with the Nyx version, which reports
# crashes via Nyx hypercalls instead of _exit(1).
export SMITE_CRASH_HANDLER=/nyx-crash-handler.so

# ASan options for CLN binaries (instrumented with -fsanitize=address):
#   abort_on_error=1  - call abort() on errors, triggering the crash handler
#   log_path          - write error details to file for crash handler to read
#   symbolize=0       - skip symbolization to maximize the chances of winning
#                       the race against snapshot reset. llvm-symbolizer can
#                       take hundreds of ms to run, which would likely cause the
#                       snapshot to reset before the crash is reported.
export ASAN_OPTIONS=abort_on_error=1:log_path=/tmp/asan.log:symbolize=0

/cln-scenario > /init.log 2>&1
