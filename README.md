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

A: Just run `cd libzstd && make libzstd` if your OS/ARCH is supported.
