#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the CLN fuzzing harness
export SMITE_NYX=1
export PATH=$PATH:/usr/local/bin

# Override the default crash handler with the Nyx version, which reports
# crashes via Nyx hypercalls instead of _exit(1).
export SMITE_CRASH_HANDLER=/nyx-crash-handler.so

/cln-scenario > /init.log 2>&1
