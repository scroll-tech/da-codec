# da-codec

## Building `libscroll_zstd.so` File.

Follow these steps to build the `.so` file:

1. Build and enter the container:
    ```
    make run
    ```

2. Change directory to rs:
    ```
    cd rs
    ```

3. Build libzstd:
    ```
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    make libzstd
    ```

## Running unit tests

Follow these steps to run unit tests:

1. Build and enter the container:
    ```
    make run
    ```

2. Set the directory for shared libraries:
    ```
    export LD_LIBRARY_PATH=${PWD}/rs:$LD_LIBRARY_PATH
    ```

3. Execute the unit tests:
    ```
    go test -v -race ./...
    ```
