#!/bin/bash

set -e

# Fixed macOS paths
LLVM_NM="/opt/homebrew/opt/llvm/bin/llvm-nm"
LLVM_OBJCOPY="/opt/homebrew/opt/llvm/bin/llvm-objcopy"

# List of library files to process
LIBRARIES=(
    "libencoder_legacy_darwin_arm64.a:scroll_legacy_"
    "libencoder_legacy_linux_amd64.a:scroll_legacy_"
    "libencoder_legacy_linux_arm64.a:scroll_legacy_"
    "libencoder_standard_darwin_arm64.a:scroll_standard_"
    "libencoder_standard_linux_amd64.a:scroll_standard_"
    "libencoder_standard_linux_arm64.a:scroll_standard_"
)

for lib_info in "${LIBRARIES[@]}"; do
    IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"
    REDEFINE_FILE="redefine_${LIB_FILE%.*}.syms"
    
    echo "Processing $LIB_FILE with prefix '$PREFIX'"
    
    # Check if library file exists
    if [ ! -f "$LIB_FILE" ]; then
        echo "Warning: Library file not found: $LIB_FILE, skipping..."
        continue
    fi
    
    # Generate redefine.syms for all potential conflicting symbols
    "$LLVM_NM" "$LIB_FILE" | awk '
    /ZSTD|HUF|FSE|ZBUFF|HIST|ERROR|MEM_|XXH|COVER|DICT|POOL|PARAM/ {
        if ($3 != "" && $3 !~ /^\./) {
            print $3 " '"$PREFIX"'" $3
        }
    }
    /^[0-9a-fA-F]+ [TDBS] / {
        if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/) {
            if ($3 ~ /^(entropy|fse|huf|zstd|hist|error|mem_|pool|param|cover|dict)/) {
                print $3 " '"$PREFIX"'" $3
            }
        }
    }
    ' | sort | uniq > "$REDEFINE_FILE"
    
    # Check if there are symbols to redefine
    if [ ! -s "$REDEFINE_FILE" ]; then
        echo "No symbols found to redefine in $LIB_FILE"
        rm -f "$REDEFINE_FILE"
        continue
    fi
    
    echo "Found $(wc -l < "$REDEFINE_FILE") symbols to redefine in $LIB_FILE"
    
    # Use llvm-objcopy to modify symbols
    "$LLVM_OBJCOPY" --redefine-syms="$REDEFINE_FILE" "$LIB_FILE" "${LIB_FILE%.*}_new.a"
    
    # Move the new file to replace the original and clean up
    mv "${LIB_FILE%.*}_new.a" "$LIB_FILE"
    rm "$REDEFINE_FILE"
    
    echo "Successfully processed $LIB_FILE"
done

echo "All libraries processed!"
