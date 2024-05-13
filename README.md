# da-codec

## Running unit tests
```
docker pull scrolltech/go-rust-builder:go-1.21-rust-nightly-2023-12-03 --platform linux/amd64
docker run -it --rm -v "$(PWD):/workspace" -w /workspace scrolltech/go-rust-builder:go-1.21-rust-nightly-2023-12-03
cd libzstd
make libzstd
cd ..
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)/libzstd
export CGO_LDFLAGS="-L$(pwd)/libzstd -Wl,-rpath=$(pwd)/libzstd"
go test -v -race ./...
```
