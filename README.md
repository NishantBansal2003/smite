# Smite

Smite is a coverage-guided fuzzing framework for Lightning Network implementations, derived from [fuzzamoto](https://github.com/dergoegge/fuzzamoto).

## Prerequisites

- x86_64 architecture
- Modern Linux operating system
- Docker
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) built from source with Nyx mode

## Quick Start

```bash
# Build the Docker image for the desired fuzz target
docker build -t smite-lnd -f workloads/lnd/Dockerfile .

# Enable the KVM VMware backdoor (required for Nyx)
./scripts/enable-vmware-backdoor.sh

# Create the Nyx sharedir
./scripts/setup-nyx.sh /tmp/smite-lnd-nyx smite-lnd ~/AFLplusplus

# Create seed corpus
mkdir -p /tmp/smite-seeds
echo 'AAAA' > /tmp/smite-seeds/seed1

# Start fuzzing
~/AFLplusplus/afl-fuzz -X -i /tmp/smite-seeds -o /tmp/smite-out -- /tmp/smite-lnd-nyx
```

## Running Modes

### Nyx Mode

Uses the [Nyx hypervisor](https://nyx-fuzz.com/) for fast snapshot-based fuzzing.
AFL++ manages the fuzzing loop and coverage feedback.

The `-X` flag enables standalone Nyx mode:

```bash
afl-fuzz -X -i <seeds> -o <output> -- <sharedir>
```

### Local Mode

This mode runs without Nyx and is used to reproduce and debug crashes.

#### Reproducing Crashes

When AFL++ finds a crash:

```bash
# Get the crash input
CRASH=/tmp/smite-out/default/crashes/id:000000,...

# Reproduce in local mode
docker run --rm -v $CRASH:/input.bin -e SMITE_INPUT=/input.bin <image> /lnd-scenario
```

### Coverage Report Mode

Generate an HTML coverage report showing which parts of LND were exercised by a fuzzing corpus:

```bash
# Generate coverage report from a fuzzing corpus
./scripts/coverage-report.sh /tmp/smite-out/default/queue/ ./coverage-report

# View the report
firefox ./coverage-report/coverage.html
```

## Project Structure

```
smite/          # Core Rust library
smite-nyx-sys/  # Nyx FFI bindings
bindings/go/    # Go bindings for CGO-based targets
workloads/
  lnd/          # LND fuzzing workload
scripts/
  setup-nyx.sh              # Helper to create Nyx sharedirs
  enable-vmware-backdoor.sh # Enable KVM VMware backdoor for Nyx
  coverage-report.sh        # Generate a coverage report
```
