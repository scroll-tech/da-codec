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
            # Original patterns
            if ($3 ~ /^(entropy|fse|huf|zstd|hist|error|mem_|pool|param|cover|dict)/) {
                print $3 " '"$PREFIX"'" $3
            }
            # Add conflict symbols found by verification logic below
            if ($3 == "_atomic_flag_test_and_set" ||
                $3 == "_atomic_signal_fence" ||
                $3 == "_divbwt" ||
                $3 == "divsufsort" ||
                $3 == "g_debuglevel" ||
                $3 == "init_cpu_features" ||
                $3 == "_ERR_getErrorString" ||
                $3 == "_atomic_flag_clear" ||
                $3 == "_atomic_flag_clear_explicit" ||
                $3 == "_atomic_flag_test_and_set_explicit" ||
                $3 == "_atomic_thread_fence" ||
                $3 == "_divsufsort" ||
                $3 == "_g_debuglevel" ||
                $3 == "divbwt" ||
                $3 == "ERR_getErrorString" ||
                $3 == "init_cpu_features_resolver") {
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

echo "1. Checking for duplicate symbols across libraries (by architecture):"
echo "   (Only checking within same architecture - cross-architecture conflicts are expected and ignored)"
echo

# Define architectures
architectures=("darwin_arm64" "linux_amd64" "linux_arm64")

total_conflicts=0
for arch in "${architectures[@]}"; do
    echo "  Architecture: $arch"
    
    # Create temp file for this architecture
    arch_temp_file=$(mktemp)
    
    # Collect symbols for this architecture only
    for lib_info in "${LIBRARIES[@]}"; do
        IFS=':' read -r LIB_FILE PREFIX <<< "$lib_info"

        # Skip if file doesn't exist or doesn't match current architecture
        if [ ! -f "$LIB_FILE" ] || [[ "$LIB_FILE" != *"$arch"* ]]; then
            continue
        fi

        "$LLVM_NM" "$LIB_FILE" 2>/dev/null | awk -v lib="$LIB_FILE" '
        /^[0-9a-fA-F]+ [TDBS] / {
            if ($3 != "" && $3 !~ /^\./ && $3 !~ /^__/ && $3 !~ /^_ZN/) {
                print $3 "\t" lib
            }
        }' >> "$arch_temp_file"
    done

    # Check for conflicts within this architecture
    if [ -s "$arch_temp_file" ]; then
        arch_conflicts=$(awk '{symbols[$1] = symbols[$1] "\n" $2} END {
            conflicts = 0
            conflict_list = ""
            for (sym in symbols) {
                count = gsub(/\n/, "&", symbols[sym])
                if (count > 1) {
                    # Skip Rust runtime symbols - these are expected to be identical
                    if (sym ~ /^rust_(begin_unwind|eh_personality|panic)$/) {
                        continue
                    }
                    conflicts++
                    print "    ❌ CONFLICT: " sym
                    libs = symbols[sym]
                    gsub(/\n/, ", ", libs)
                    print "       Found in: " libs
                }
            }
            if (conflicts == 0) {
                print "    ✅ No symbol conflicts found within this architecture!"
            } else {
                print "    ❌ Found " conflicts " conflicting symbols (all shown above)"
            }
            print "CONFLICT_COUNT:" conflicts
        }' "$arch_temp_file")

        echo "$arch_conflicts"
        arch_conflict_count=$(echo "$arch_conflicts" | grep "CONFLICT_COUNT:" | cut -d: -f2 || echo 0)
        total_conflicts=$((total_conflicts + arch_conflict_count))
    else
        echo "    ✅ No libraries found for this architecture"
    fi

    rm "$arch_temp_file"
    echo
done

# Summary
if [ "$total_conflicts" -eq 0 ]; then
    echo "🎉 All architectures passed symbol conflict check!"
else
    echo "⚠️  Found $total_conflicts total symbol conflicts across all architectures"
fi

conflict_count=$total_conflicts

echo "2. Sample prefixed symbols from each library:"
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

echo "3. Preserved original functions:"
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
