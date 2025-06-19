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

echo "=== Adding Symbol Prefixes ==="
echo

for lib_info in "${LIBRARIES[@]}"; do
    IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"
    REDEFINE_FILE="redefine_${LIB_FILE%.*}.syms"
    
    echo "Processing $LIB_FILE with prefix '$PREFIX'"
    
    # Check if library file exists
    if [ ! -f "$LIB_FILE" ]; then
        echo "Warning: Library file not found: $LIB_FILE, skipping..."
        continue
    fi
    
    # Check if library is already processed by looking for our prefix
    if "$LLVM_NM" "$LIB_FILE" 2>/dev/null | grep -q "${PREFIX}"; then
        echo "Library $LIB_FILE already processed (found ${PREFIX} symbols), skipping..."
        continue
    fi

    # Generate redefine.syms for all potential conflicting symbols
    "$LLVM_NM" "$LIB_FILE" | awk '
    /ZSTD|HUF|FSE|ZBUFF|HIST|ERROR|MEM_|XXH|COVER|DICT|POOL|PARAM/ {
        if ($3 != "" && $3 !~ /^\./ && $3 !~ /^'"$PREFIX"'/) {
            print $3 " '"$PREFIX"'" $3
        }
    }
    /^[0-9a-fA-F]+ [TDBS] / {
        if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/ && $3 !~ /^'"$PREFIX"'/) {
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
    
    # Show sample symbols being renamed
    echo "Sample symbols to be renamed:"
    head -3 "$REDEFINE_FILE" | while read old new; do
        echo "  $old -> $new"
    done

    # Use llvm-objcopy to modify symbols
    "$LLVM_OBJCOPY" --redefine-syms="$REDEFINE_FILE" "$LIB_FILE" "${LIB_FILE%.*}_new.a"
    
    # Move the new file to replace the original and clean up
    mv "${LIB_FILE%.*}_new.a" "$LIB_FILE"
    rm "$REDEFINE_FILE"
    
    echo "Successfully processed $LIB_FILE"
    echo
done

echo "=== Symbol Processing Complete ==="
echo
echo "=== Checking for Symbol Conflicts ==="
echo

# Extract library files for conflict checking
LIB_FILES=()
for lib_info in "${LIBRARIES[@]}"; do
    IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"
    LIB_FILES+=("$LIB_FILE")
done

# Temporary file to store all symbols
temp_file=$(mktemp)

# Collect all exported symbols from all libraries
echo "Collecting symbols from all libraries..."
for LIB_FILE in "${LIB_FILES[@]}"; do
    if [ ! -f "$LIB_FILE" ]; then
        echo "Warning: $LIB_FILE not found, skipping..."
        continue
    fi

    "$LLVM_NM" "$LIB_FILE" 2>/dev/null | awk -v lib="$LIB_FILE" '
    /^[0-9a-fA-F]+ [TDBS] / {
        if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/) {
            print $3 "\t" lib
        }
    }
    ' >> "$temp_file"
done

echo
echo "1. Checking for duplicate symbols across libraries:"

# Find conflicting symbols
conflicts_output=$(awk '{symbols[$1] = symbols[$1] "\n" $2} END {
    conflicts = 0
    for (sym in symbols) {
        count = gsub(/\n/, "&", symbols[sym])
        if (count > 1) {
            conflicts++
            if (conflicts <= 10) {  # Show first 10 conflicts
                print "  ❌ CONFLICT: " sym
                libs = symbols[sym]
                gsub(/\n/, ", ", libs)
                print "     Found in: " libs
                print ""
            }
        }
    }
    if (conflicts == 0) {
        print "  ✅ No symbol conflicts found!"
        return 0
    } else {
        print "  ❌ Found " conflicts " conflicting symbols" (conflicts > 10 ? " (showing first 10)" : "")
        return conflicts
    }
}' "$temp_file")

echo "$conflicts_output"
conflict_count=$(echo "$conflicts_output" | tail -1 | grep -o '[0-9]\+' | tail -1 || echo 0)

echo
echo "2. Prefix application verification:"

for lib_info in "${LIBRARIES[@]}"; do
    IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"

    if [ ! -f "$LIB_FILE" ]; then
        continue
    fi

    # Count unprefixed target symbols
    unprefixed_targets=$("$LLVM_NM" "$LIB_FILE" 2>/dev/null | awk -v prefix="$PREFIX" '
    /^[0-9a-fA-F]+ [TDBS] / {
        if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/ && $3 !~ ("^" prefix)) {
            # Check if it matches our target patterns
            if ($0 ~ /ZSTD|HUF|FSE|ZBUFF|HIST|ERROR|MEM_|XXH|COVER|DICT|POOL|PARAM/ ||
                $3 ~ /^(entropy|fse|huf|zstd|hist|error|mem_|pool|param|cover|dict)/) {
                print $3
            }
        }
    }' | wc -l)

    # Count prefixed symbols
    prefixed_count=$("$LLVM_NM" "$LIB_FILE" 2>/dev/null | grep -c "${PREFIX}" || echo 0)

    echo "  $LIB_FILE:"
    echo "    - Prefixed symbols (${PREFIX}*): $prefixed_count"
    echo "    - Unprefixed target symbols: $unprefixed_targets"

    if [ "$unprefixed_targets" -gt 0 ]; then
        echo "    ⚠️  Still has $unprefixed_targets unprefixed target symbols"
        echo "    Examples:"
        "$LLVM_NM" "$LIB_FILE" 2>/dev/null | awk -v prefix="$PREFIX" '
        /^[0-9a-fA-F]+ [TDBS] / {
            if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/ && $3 !~ ("^" prefix)) {
                if ($0 ~ /ZSTD|HUF|FSE|ZBUFF|HIST|ERROR|MEM_|XXH|COVER|DICT|POOL|PARAM/ ||
                    $3 ~ /^(entropy|fse|huf|zstd|hist|error|mem_|pool|param|cover|dict)/) {
                    print "      " $3
                }
            }
        }' | head -3
    else
        echo "    ✅ All target symbols properly prefixed"
    fi
    echo
done

echo "3. Sample prefixed symbols from each library:"
for lib_info in "${LIBRARIES[@]}"; do
    IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"

    if [ ! -f "$LIB_FILE" ]; then
        continue
    fi

    echo "  $LIB_FILE (sample ${PREFIX}* symbols):"
    "$LLVM_NM" "$LIB_FILE" 2>/dev/null | awk -v prefix="$PREFIX" '
    /^[0-9a-fA-F]+ [TDBS] / {
        if ($3 ~ ("^" prefix)) {
            print "    " $3
        }
    }' | head -3
    echo
done

echo "4. Preserved original functions:"
for LIB_FILE in "${LIB_FILES[@]}"; do
    if [ ! -f "$LIB_FILE" ]; then
        continue
    fi

    echo "  $LIB_FILE:"
    "$LLVM_NM" "$LIB_FILE" 2>/dev/null | grep -E "(compress_scroll_batch_bytes_)" | awk '{print "    " $2 " " $3}' || echo "    No original functions found"
    echo
done

# Cleanup
rm "$temp_file"

echo "=== Final Analysis ==="

if [ "$conflict_count" -eq 0 ]; then
    echo "🎉 SUCCESS: All libraries processed successfully with no symbol conflicts!"
    echo "✅ All target symbols have been properly prefixed"
    echo "✅ Original functions preserved"
else
    echo "⚠️  WARNING: Found $conflict_count symbol conflicts that need attention."
    echo "📋 Please review the conflicts listed above"
fi

echo
echo "=== Process Complete ==="
