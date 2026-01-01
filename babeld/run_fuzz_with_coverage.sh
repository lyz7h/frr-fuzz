#!/bin/bash

# Fuzz testing script with periodic coverage collection
# Runs fuzz for 24 hours
# - First 10 minutes: collect coverage every 1 minute
# - After 10 minutes: collect coverage every 10 minutes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
FUZZ_DURATION=86400              # Total fuzz duration in seconds (24 hours)
INITIAL_PHASE_DURATION=600       # First phase duration in seconds (10 minutes)
INITIAL_INTERVAL=60              # Coverage interval during first phase (1 minute)
NORMAL_INTERVAL=600              # Coverage interval after first phase (10 minutes)
OUTPUT_CSV="coverage_report.csv"
BINARY_PATH=".libs/babeld"

# Clean up previous runs
rm -rf profraw
rm -rf crashes_and_corpus

mkdir -p profraw
mkdir -p crashes_and_corpus

# Set up profiling
export LLVM_PROFILE_FILE="$PWD/profraw/frr-%p.profraw"

# Create CSV header
echo "timestamp,lines_hit,lines_total,lines_percent,functions_hit,functions_total,functions_percent,branches_hit,branches_total,branches_percent" > "$OUTPUT_CSV"

# Function to collect coverage
collect_coverage() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    cd "$SCRIPT_DIR/profraw"
    
    # Check if there are any profraw files
    if ! ls frr-*.profraw 1>/dev/null 2>&1; then
        echo "No profraw files found yet..."
        cd "$SCRIPT_DIR"
        return
    fi
    
    # Merge profraw files
    sudo llvm-profdata merge -sparse frr-*.profraw -o frr.profdata 2>/dev/null
    
    if [ ! -f frr.profdata ]; then
        echo "Failed to create profdata..."
        cd "$SCRIPT_DIR"
        return
    fi
    
    # Get coverage report
    local report=$(llvm-cov report "$SCRIPT_DIR/$BINARY_PATH" -instr-profile=frr.profdata 2>/dev/null)
    
    # Parse the TOTAL line from llvm-cov report
    # Format: TOTAL Regions_Total Regions_Missed Regions_Cover% Functions_Total Functions_Missed Functions_Cover% Lines_Total Lines_Missed Lines_Cover% Branches_Total Branches_Missed Branches_Cover%
    local total_line=$(echo "$report" | grep "^TOTAL" | tail -1)
    
    if [ -z "$total_line" ]; then
        echo "Could not parse coverage report..."
        cd "$SCRIPT_DIR"
        return
    fi
    
    # Extract values - llvm-cov report format:
    # TOTAL  [Regions_Total] [Regions_Missed] [Regions%] [Func_Total] [Func_Missed] [Func%] [Lines_Total] [Lines_Missed] [Lines%] [Branch_Total] [Branch_Missed] [Branch%]
    # Columns: 1=TOTAL, 2=Regions_Total, 3=Regions_Missed, 4=Regions%, 5=Func_Total, 6=Func_Missed, 7=Func%, 8=Lines_Total, 9=Lines_Missed, 10=Lines%, 11=Branch_Total, 12=Branch_Missed, 13=Branch%
    
    local functions_total=$(echo "$total_line" | awk '{print $5}')
    local functions_missed=$(echo "$total_line" | awk '{print $6}')
    local functions_percent=$(echo "$total_line" | awk '{print $7}' | tr -d '%')
    
    local lines_total=$(echo "$total_line" | awk '{print $8}')
    local lines_missed=$(echo "$total_line" | awk '{print $9}')
    local lines_percent=$(echo "$total_line" | awk '{print $10}' | tr -d '%')
    
    local branches_total=$(echo "$total_line" | awk '{print $11}')
    local branches_missed=$(echo "$total_line" | awk '{print $12}')
    local branches_percent=$(echo "$total_line" | awk '{print $13}' | tr -d '%')
    
    # Calculate hit values
    local lines_hit=$((lines_total - lines_missed))
    local functions_hit=$((functions_total - functions_missed))
    local branches_hit=$((branches_total - branches_missed))
    
    # Handle cases where values might be empty or invalid
    if [ -z "$lines_total" ] || [ "$lines_total" = "-" ]; then
        echo "Could not parse coverage values..."
        cd "$SCRIPT_DIR"
        return
    fi
    
    # Write to CSV
    echo "$timestamp,$lines_hit,$lines_total,$lines_percent,$functions_hit,$functions_total,$functions_percent,$branches_hit,$branches_total,$branches_percent" >> "$SCRIPT_DIR/$OUTPUT_CSV"
    
    echo "[$timestamp] Coverage collected - Lines: $lines_hit/$lines_total ($lines_percent%), Functions: $functions_hit/$functions_total ($functions_percent%)"
    
    cd "$SCRIPT_DIR"
}

echo "Starting fuzz testing with coverage collection..."
echo "Total duration: $((FUZZ_DURATION / 3600)) hours"
echo "First 10 minutes: collect every 1 minute"
echo "After 10 minutes: collect every 10 minutes"
echo "Output CSV: $OUTPUT_CSV"
echo ""

# Start fuzzer in background
./babeld crashes_and_corpus/ ../corpus/babel -max_total_time=$FUZZ_DURATION -fork=1 \
    -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -timeout=10 2>&1 | tee ./fuzz.log &

FUZZ_PID=$!

echo "Fuzzer started with PID: $FUZZ_PID"
echo ""

# Wait a bit for fuzzer to start generating data
sleep 5

elapsed=0

# Phase 1: First 10 minutes - collect every 1 minute
echo "=== Phase 1: Collecting coverage every 1 minute for 10 minutes ==="
while [ $elapsed -lt $INITIAL_PHASE_DURATION ] && [ $elapsed -lt $FUZZ_DURATION ]; do
    sleep $INITIAL_INTERVAL
    elapsed=$((elapsed + INITIAL_INTERVAL))
    
    echo "Collecting coverage at $((elapsed / 60)) minute(s)..."
    collect_coverage
done

# Phase 2: After 10 minutes - collect every 10 minutes
echo ""
echo "=== Phase 2: Collecting coverage every 10 minutes ==="
while [ $elapsed -lt $FUZZ_DURATION ]; do
    sleep $NORMAL_INTERVAL
    elapsed=$((elapsed + NORMAL_INTERVAL))
    
    local_hours=$((elapsed / 3600))
    local_mins=$(((elapsed % 3600) / 60))
    echo "Collecting coverage at ${local_hours}h ${local_mins}m..."
    collect_coverage
done

# Wait for fuzzer to complete
wait $FUZZ_PID 2>/dev/null

echo ""
echo "Fuzz testing completed!"
echo "Coverage report saved to: $OUTPUT_CSV"
echo ""
echo "Coverage Summary:"
cat "$OUTPUT_CSV"
