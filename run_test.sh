#!/bin/bash

# Save the root directory of the project
ROOT_DIR=$(pwd)

# Compile libzstd
cd $ROOT_DIR/libzstd
make libzstd

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/

# Run module tests
cd $ROOT_DIR
env GO111MODULE=on go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
