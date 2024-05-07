#!/bin/bash

# Compile libzstd
cd libzstd && cargo build --release && cd ..
sudo cp -f $(pwd)/libzstd/target/release/libscroll_zstd.so $(pwd)/
find $(pwd)/libzstd/target/release | grep libzktrie.so | xargs -I{} cp -f {} $(pwd)/
sudo cp -f libscroll_zstd.so libzktrie.so /usr/local/lib

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

# Run module tests
env GO111MODULE=on go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
