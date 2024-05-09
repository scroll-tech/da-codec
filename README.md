# da-codec

## Running unit tests
```
make run
cd libzstd
make libzstd
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)
export CGO_LDFLAGS="-L$(pwd) -lscroll_zstd -lzktrie"
cd ..
go test -v -race ./...
```
