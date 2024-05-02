#!/bin/bash

# Save the root directory of the project
ROOT_DIR=$(pwd)

# Set the environment variable
export LD_LIBRARY_PATH=$ROOT_DIR/rs:$LD_LIBRARY_PATH

# Compile libzstd
cd $ROOT_DIR/rs
make libzstd

# Run unit tests
cd $ROOT_DIR
go test -v -race -gcflags="-l" -ldflags="-s=false" -coverprofile=coverage.txt -covermode=atomic ./...
