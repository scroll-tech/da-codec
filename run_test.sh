#!/bin/bash

# Compile libzstd
cd libzstd && cargo build --release && cd ..
sudo mkdir -p /scroll/lib/
sudo cp -f $(pwd)/libzstd/target/release/libscroll_zstd.so /scroll/lib/
find $(pwd)/libzstd/target/release -name 'libzktrie.so' | xargs -I{} sudo cp -f {} /scroll/lib/

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/scroll/lib/
export CGO_LDFLAGS="-L/scroll/lib/ -Wl,-rpath,/scroll/lib/"

# Run module tests
go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
