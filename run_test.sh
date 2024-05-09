#!/bin/bash

# Compile libzstd
cd libzstd && cargo build --release && cd ..
sudo cp -f $(pwd)/libzstd/target/release/libscroll_zstd.so $(pwd)/
find $(pwd)/libzstd/target/release | grep libzktrie.so | xargs -I{} cp -f {} $(pwd)/

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)
export CGO_LDFLAGS="-L$(pwd) -Wl,-rpath=$(pwd)"

# Run module tests
go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
