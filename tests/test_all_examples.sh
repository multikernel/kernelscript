#!/bin/bash
#
# Copyright 2025 Multikernel Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


# Test script to compile all examples in the examples/ directory
# 
# This script:
# 1. Builds the KernelScript compiler using dune
# 2. Compiles each .ks file in the examples/ directory to C code
# 3. Runs `make` to compile the generated C code
# 4. Continues compilation even if some examples fail
# 5. Shows detailed error information for failed examples
# 6. Provides a summary of successes and failures (both KS and C)
# 7. Cleans up all generated output files
#
# Usage: ./test_all_examples.sh
# 
# The script should be run from the tests/ directory and will automatically
# navigate to the project root to perform the compilation.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize counters
success_count=0
ks_failure_count=0
c_failure_count=0
ks_failed_examples=()
c_failed_examples=()

# Create a temporary directory for outputs
temp_dir=$(mktemp -d)
echo "Using temporary directory: $temp_dir"

# Function to cleanup
cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf "$temp_dir"
    echo "Cleanup completed."
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Change to project root directory
cd "$(dirname "$0")/.."

echo "============================================="
echo "🚀 KernelScript Examples Compilation Test"
echo "============================================="

# Build the project first
echo "Building KernelScript compiler..."
if eval $(opam env) && dune build; then
    echo -e "${GREEN}✅ Build successful${NC}"
else
    echo -e "${RED}❌ Build failed - cannot proceed${NC}"
    exit 1
fi

echo ""
echo "Compiling examples (KernelScript → C → Binary)..."
echo "---------------------------------------------------"

# Get the path to the built executable
executable_path="./_build/default/src/main.exe"

# Check if executable exists
if [ ! -f "$executable_path" ]; then
    echo -e "${RED}❌ Executable not found at $executable_path${NC}"
    exit 1
fi

# Iterate through all .ks files in examples directory
for example_file in examples/*.ks; do
    # Extract just the filename without path
    filename=$(basename "$example_file")
    
    # Create output directory for this example
    output_dir="$temp_dir/$filename"
    mkdir -p "$output_dir"
    
    echo -n "📝 Compiling $filename... "
    
    # Try to compile the KernelScript source to C
    if "$executable_path" compile "$example_file" -o "$output_dir" > "$temp_dir/${filename}_ks.log" 2>&1; then
        echo -n -e "${GREEN}KS✅${NC} "
        
        # Now try to compile the generated C code with make
        echo -n "C... "
        if (cd "$output_dir" && make > "$temp_dir/${filename}_c.log" 2>&1); then
            echo -e "${GREEN}✅ SUCCESS${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}❌ C FAILED${NC}"
            c_failure_count=$((c_failure_count + 1))
            c_failed_examples+=("$filename")
            
            # Show C compilation error details
            echo -e "${RED}   C compilation error details:${NC}"
            head -n 10 "$temp_dir/${filename}_c.log" | sed 's/^/   /'
            if [ $(wc -l < "$temp_dir/${filename}_c.log") -gt 10 ]; then
                echo "   ... (truncated, see full log in temp directory)"
            fi
        fi
    else
        echo -e "${RED}❌ KS FAILED${NC}"
        ks_failure_count=$((ks_failure_count + 1))
        ks_failed_examples+=("$filename")
        
        # Show KernelScript compilation error details
        echo -e "${RED}   KernelScript compilation error details:${NC}"
        head -n 10 "$temp_dir/${filename}_ks.log" | sed 's/^/   /'
        if [ $(wc -l < "$temp_dir/${filename}_ks.log") -gt 10 ]; then
            echo "   ... (truncated, see full log in temp directory)"
        fi
    fi
done

echo ""
echo "============================================="
echo "📊 COMPILATION SUMMARY"
echo "============================================="

total_examples=$((success_count + ks_failure_count + c_failure_count))
total_failures=$((ks_failure_count + c_failure_count))
echo -e "Total examples: ${YELLOW}$total_examples${NC}"
echo -e "Fully successful (KS + C): ${GREEN}$success_count${NC}"
echo -e "KernelScript failures: ${RED}$ks_failure_count${NC}"
echo -e "C compilation failures: ${RED}$c_failure_count${NC}"
echo -e "Total failures: ${RED}$total_failures${NC}"

if [ $ks_failure_count -gt 0 ]; then
    echo ""
    echo -e "${RED}KernelScript compilation failures:${NC}"
    for failed in "${ks_failed_examples[@]}"; do
        echo -e "${RED}  - $failed${NC}"
    done
fi

if [ $c_failure_count -gt 0 ]; then
    echo ""
    echo -e "${RED}C compilation failures:${NC}"
    for failed in "${c_failed_examples[@]}"; do
        echo -e "${RED}  - $failed${NC}"
    done
fi

if [ $total_failures -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}⚠️  Some examples failed to compile${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}🎉 All examples compiled successfully (both KS and C)!${NC}"
fi

echo ""
echo "=============================================" 