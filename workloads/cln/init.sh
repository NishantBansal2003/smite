#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the CLN fuzzing harness
export SMITE_NYX=1
export PATH=$PATH:/usr/local/bin
/cln-scenario > /init.log 2>&1
