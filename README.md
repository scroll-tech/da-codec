```markdown
# da-codec

Scroll's DA (Data-Aware) encoding and decoding libraries provide efficient serialization and transmission mechanisms suitable for various applications in data handling.

## Getting Started

To use the DA codec library in your project, follow these steps:

1. Install Go on your machine if you haven't already: [Installing Go](https://golang.org/doc/install).
2. Clone this repository:
   ```bash
   git clone https://github.com/scroll-tech/da-codec.git
   ```
3. Navigate to the project directory:
   ```bash
   cd da-codec
   ```
4. Import the library in your Go project:
   ```go
   import "path/to/your/da-codec"
   ```

5. Use the encoding and decoding functions as needed in your application.
## Running Unit Tests

To ensure code integrity, run the following command:
```bash
go test -v -race ./...
```
Make sure you have Go installed on your system. This command runs all tests in the project with verbose output and race condition detection.

## FAQ

**Q: Why does the repo contain `libscroll_zstd*.a` binary files?**  
A: This simplifies package installation with `go get` without the need to perform additional steps for building the `libscroll_zstd*.a` files.

**Q: Which platforms/architectures are supported?**  
A: `linux/amd64`, `linux/arm64`, `darwin/arm64`. Pull requests for other platforms/architectures are welcome.

**Q: I don't trust `libscroll_zstd*.a` binary files from the repo or these files don't work on my OS/ARCH. How can I rebuild them?**  
A: Run the following command if your OS/ARCH is supported:
```bash
cd libzstd && make libzstd
```

## Contributing

We welcome contributions to the `da-codec` library! If you have suggestions for improvements or find bugs, please feel free to open an issue or submit a pull request. Ensure you follow the coding standards and include relevant tests for your changes.
```