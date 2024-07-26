# Generate redefine.syms for linux_amd64
/opt/homebrew/opt/llvm/bin/llvm-nm libscroll_zstd_linux_amd64.a | awk '/ZSTD|HUF|FSE/ {if ($3 != "") print $3 " scroll_" $3}' | sort | uniq > redefine_linux_amd64.syms

# Use llvm-objcopy to modify symbols for linux_amd64
llvm-objcopy --redefine-syms=redefine_linux_amd64.syms libscroll_zstd_linux_amd64.a libscroll_zstd_linux_amd64_new.a

# Move the new file to replace the original and clean up
mv libscroll_zstd_linux_amd64_new.a libscroll_zstd_linux_amd64.a
rm redefine_linux_amd64.syms

# Generate redefine.syms for linux_arm64
/opt/homebrew/opt/llvm/bin/llvm-nm libscroll_zstd_linux_arm64.a | awk '/ZSTD|HUF|FSE/ {if ($3 != "") print $3 " scroll_" $3}' | sort | uniq > redefine_linux_arm64.syms

# Use llvm-objcopy to modify symbols for linux_arm64
llvm-objcopy --redefine-syms=redefine_linux_arm64.syms libscroll_zstd_linux_arm64.a libscroll_zstd_linux_arm64_new.a

# Move the new file to replace the original and clean up
mv libscroll_zstd_linux_arm64_new.a libscroll_zstd_linux_arm64.a
rm redefine_linux_arm64.syms

# Generate redefine.syms for darwin_arm64
/opt/homebrew/opt/llvm/bin/llvm-nm libscroll_zstd_darwin_arm64.a | awk '/ZSTD|HUF|FSE/ {if ($3 != "") print $3 " scroll_" $3}' | sort | uniq > redefine_darwin_arm64.syms

# Use llvm-objcopy to modify symbols for darwin_arm64
llvm-objcopy --redefine-syms=redefine_darwin_arm64.syms libscroll_zstd_darwin_arm64.a libscroll_zstd_darwin_arm64_new.a

# Move the new file to replace the original and clean up
mv libscroll_zstd_darwin_arm64_new.a libscroll_zstd_darwin_arm64.a
rm redefine_darwin_arm64.syms
