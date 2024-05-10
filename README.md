# da-codec

## Running unit tests
```
make run
cd libzstd
make libzstd
cd ..
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)/libzstd
export CGO_LDFLAGS="-L$(pwd)/libzstd -Wl,-rpath=$(pwd)/libzstd"
go test -v -race ./...
```
