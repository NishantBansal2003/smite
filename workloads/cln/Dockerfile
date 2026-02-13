FROM debian:bookworm AS builder

# Build arguments
ARG LLVM_V=19
ARG CLN_VERSION=v25.12.1
ARG BITCOIN_VERSION=29.2

ENV LLVM_V=${LLVM_V}

# Install LLVM toolchain (using modern key method without gnupg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    wget \
    ca-certificates
RUN mkdir -p /etc/apt/keyrings && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/keyrings/llvm.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/llvm.asc] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_V} main" > /etc/apt/sources.list.d/llvm.list

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    clang-${LLVM_V} \
    lld-${LLVM_V} \
    llvm-${LLVM_V}-dev \
    curl \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    libsqlite3-dev \
    libsodium-dev \
    libssl-dev \
    zlib1g-dev \
    gettext \
    jq \
    lowdown \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install AFL++ from source (need afl-clang-fast for C instrumentation).
# Builds just the compiler wrappers, not QEMU/Nyx support.
RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /AFLplusplus
WORKDIR /AFLplusplus
RUN CC=clang-${LLVM_V} CXX=clang++-${LLVM_V} \
    LLVM_CONFIG=llvm-config-${LLVM_V} \
    make -j$(nproc) && make install

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly && rustup default nightly

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Clone CLN and build with AFL instrumentation.
RUN git clone --depth 1 --branch ${CLN_VERSION} --recurse-submodules \
    https://github.com/ElementsProject/lightning.git /cln
WORKDIR /cln
RUN pip3 install --break-system-packages mako
RUN CC=afl-clang-fast ./configure --prefix=/usr/local --disable-rust
RUN make -j$(nproc) install

# Copy smite workspace files and build the Rust cln-scenario binary
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-scenarios/ smite-scenarios/
COPY smite-nyx-sys/ smite-nyx-sys/
RUN TARGET_PATH=/usr/local/bin/lightningd \
    cargo build -p smite-scenarios --bin cln --release --features nyx

# Build crash handler shared libraries, LD_PRELOADed into CLN to bypass its
# blocking crashdump signal handler. Two variants:
#   nyx-crash-handler.so  - reports crashes via Nyx hypercalls
#   crash-handler.so      - calls _exit(1), for local reproduction
RUN clang-${LLVM_V} -fPIC -DENABLE_NYX -DCATCH_SIGNALS -DNO_PT_NYX -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /nyx-crash-handler.so && \
    clang-${LLVM_V} -fPIC -DCATCH_SIGNALS -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /crash-handler.so

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    libsqlite3-0 \
    libsodium23 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy CLN binaries (subdaemons and plugins in libexec/)
COPY --from=builder /usr/local/bin/lightningd /usr/local/bin/lightningd
COPY --from=builder /usr/local/bin/lightning-cli /usr/local/bin/lightning-cli
COPY --from=builder /usr/local/libexec/c-lightning/ /usr/local/libexec/c-lightning/

# Copy Bitcoin Core binaries
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# Copy crash handlers and cln-scenario binary
COPY --from=builder /nyx-crash-handler.so /crash-handler.so /
COPY --from=builder /smite/target/release/cln /cln-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
# ClnTarget forwards this as LD_PRELOAD on lightningd only, so it doesn't
# interfere with helper processes (lightning-cli, bitcoin-cli).
ENV SMITE_CRASH_HANDLER=/crash-handler.so

# Copy the init script
COPY workloads/cln/init.sh /init.sh
RUN chmod +x /init.sh /cln-scenario

WORKDIR /
