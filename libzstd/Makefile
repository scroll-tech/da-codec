.PHONY: libzstd libzstddbg

clean:
	rm -f *.a *.so
	cargo clean

libzstd:
	cargo build --release
	cp -f $(PWD)/target/release/libscroll_zstd.so $(PWD)/

libzstddbg:
	cargo build
	cp -f $(PWD)/target/debug/libscroll_zstd.so $(PWD)/
