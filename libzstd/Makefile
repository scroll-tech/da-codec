.PHONY: libzstd libzstddbg

clean:
	rm -rf *.a *.so target
	cargo clean

libzstd:
	cargo build --release

libzstddbg:
	cargo build
