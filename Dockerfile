FROM ubuntu:25.04

RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get update && \
    apt-get install -y \
        autoconf automake git libtool libssl-dev pkg-config \
        libnfc-dev libnfc-bin libnfc-examples \
        git \
        openssl libcrypt-dev libssl-dev \
        build-essential ninja-build cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /libfreefare
ADD https://github.com/nfc-tools/libfreefare.git ./
RUN autoreconf -vis && \
    ./configure --prefix=/usr && \
    make && \
    make install

WORKDIR /app
ADD https://github.com/docopt/docopt.cpp.git ./docopt.cpp
ADD CMakeLists.txt ./
ADD src/ ./src
RUN ls -la ./
WORKDIR /app/build
RUN cmake .. -G Ninja && \
    cmake --build . -j$(nproc)