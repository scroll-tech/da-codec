#!/bin/bash

# Compile libzstd
cd libzstd && cargo build --release && cd ..
sudo cp -f $(pwd)/libzstd/target/release/libscroll_zstd.so $(pwd)/
find $(pwd)/libzstd/target/release | grep libzktrie.so | xargs -I{} cp -f {} $(pwd)/
sudo cp -f libscroll_zstd.so libzktrie.so /workspace/lib

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/workspace/lib

# Set CGO_LDFLAGS
export CGO_LDFLAGS="-L/workspace/lib -lscroll_zstd -lzktrie"

# Run module tests
go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
