# da-codec

Scroll's DA encoding/decoding libraries.

## Running unit tests
```
go test -v -race ./...
```

## FAQ

**Q: Why the repo contains `libscroll_zstd*.a` binary files?**

A: This simplifies package installation with `go get` without the need to perform additional steps for building the `libscroll_zstd*.a`.

**Q: Which platforms/architectures are supported?**

A: `linux/amd64`, `linux/arm64`, `darwin/arm64`. Pull requests for other platforms/architectures are accepted.

**Q: I don't trust `libscroll_zstd*.a` binary files from the repo or these files don't work on my OS/ARCH. How to rebuild them?**

A: To rebuild the libraries for your platform:

1. Build the legacy encoder:

    ```bash
    cd libzstd/encoder-legacy
    make install
    ```

2. Build the standard encoder:

    ```bash
    cd libzstd/encoder-standard
    make install
    ```

3. Add symbol prefixes to avoid conflicts:

    ```bash
    cd encoding/zstd
    ./add_symbol_prefix.sh
    ```

    **Note**: The symbol prefix script currently only works on macOS. For Linux builds, perform steps 1-2 in Docker, then run step 3 on macOS.

    For macOS builds, ensure you have Rust and necessary build tools installed:

    ```bash
    # Install Rust if not already installed
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

    For Linux builds, use Docker with build dependencies:

    ```bash
    # Linux ARM64
    docker run -it --rm --platform linux/arm64 -v $(pwd):/workspace -w /workspace rust:1.75-slim bash
    apt update && apt install -y build-essential

    # Linux AMD64
    docker run -it --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:1.75-slim bash
    apt update && apt install -y build-essential
    ```
