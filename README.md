# da-codec

## Running unit tests

Follow these steps to run unit tests:

1. Build and enter the container:
    ```
    make run
    ```

2. Change directory to libzstd:
    ```
    cd libzstd
    ```

3. Build libzstd:
    ```
    make libzstd
    ```

4. Execute the unit tests:
    ```
    cd ..
    go test -v -race ./...
    ```
