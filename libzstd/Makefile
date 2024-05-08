.PHONY: libzstd libzstddbg

clean:
	rm -f *.a *.so
	cargo clean

libzstd:
	cargo build --release
	cp -f $(PWD)/target/release/libscrollzstd.so $(PWD)/
	find $(PWD)/target/release | grep libzktrie.so | xargs -I{} cp -f {} $(PWD)/
	cp -f libscrollzstd.so libzktrie.so /usr/local/lib

libzstddbg:
	cargo build
	cp -f $(PWD)/target/debug/libscrollzstd.so $(PWD)/
	find $(PWD)/target/debug | grep libzktrie.so | xargs -I{} cp -f {} $(PWD)/
	cp -f libscrollzstd.so libzktrie.so /usr/local/lib
