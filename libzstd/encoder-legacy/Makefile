.PHONY: all clean build install

# Detect platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
    ifeq ($(UNAME_M),x86_64)
        PLATFORM := linux_amd64
    else ifeq ($(UNAME_M),aarch64)
        PLATFORM := linux_arm64
    endif
else ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        PLATFORM := darwin_arm64
    else ifeq ($(UNAME_M),x86_64)
        PLATFORM := darwin_amd64
    endif
endif

TARGET_DIR := ../../encoding/zstd

all: build

build:
	@echo "Building legacy encoder for $(PLATFORM)..."
	cargo build --release

install: build
	@echo "Installing legacy library to $(TARGET_DIR)..."
	cp target/release/libencoder_legacy.a $(TARGET_DIR)/libencoder_legacy_$(PLATFORM).a
	@echo "Legacy installation complete!"

clean:
	cargo clean
	rm -f $(TARGET_DIR)/libencoder_legacy_$(PLATFORM).a

info:
	@echo "Legacy encoder - Platform: $(PLATFORM)"
	@echo "Target directory: $(TARGET_DIR)"
