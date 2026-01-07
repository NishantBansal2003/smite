# LND Workload

This workload fuzzes [LND](https://github.com/lightningnetwork/lnd) by
connecting via the Noise protocol and then sending unstructured bytes to LND.

## How it works

1. Starts bitcoind in regtest mode
2. Starts LND connected to bitcoind
3. Connects to LND over TCP
4. Does the Noise protocol handshake using LND's brontide library
5. Exchanges `init` messages
6. Creates a VM snapshot
7. Encrypts and sends raw fuzz input bytes over the connection
8. Triggers coverage collection via `lncli getinfo`
9. Restores the VM snapshot to fuzz with a new input

## Building

From the repository root:

```bash
docker build -t smite-lnd -f workloads/lnd/Dockerfile .
```

## Running

See the [main README](../../README.md) for local mode and Nyx mode instructions.

## Coverage Instrumentation

LND is built with `-tags=libfuzzer -gcflags=all=-d=libfuzzer` to enable Go's
built-in libfuzzer instrumentation. The `0001-sancov.patch` adds a `sancov.go`
file that copies Go's coverage data to AFL's shared memory region.
