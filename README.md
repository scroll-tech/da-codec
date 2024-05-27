# da-codec

## Running unit tests
```
# Prepare dev-container
docker pull scrolltech/go-rust-builder:go-1.21-rust-nightly-2023-12-03 --platform linux/amd64
docker run -it --rm -v "$(PWD):/workspace" -w /workspace scrolltech/go-rust-builder:go-1.21-rust-nightly-2023-12-03

# Compile libzstd
cd libzstd && make libzstd && cd ..
mkdir -p /scroll/lib/
cp -f $(pwd)/libzstd/target/release/libscroll_zstd.so /scroll/lib/

# Set the environment variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/scroll/lib/
export CGO_LDFLAGS="-L/scroll/lib/ -Wl,-rpath,/scroll/lib/"

# Run unit tests
go test -v -race ./...
```
