#!/bin/bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)


# Check that /target folder exists
if [ ! -d "$ROOT/target" ]; then
    echo "Error: /target folder does not exist - run compile"
    exit 1
fi

# Circuits list provided by ci-circuits.sh
mapfile -t CIRCUITS < "$ROOT/scripts/helpers/ci-circuits.txt"


mkdir -p "$ROOT/nargo-info"

export ROOT
export -f

for circuit in "${CIRCUITS[@]}"; do
    echo "Info $circuit"
    nargo info --package "$circuit" --json > "$ROOT/nargo-info/$circuit.json"
done

# Generate a json file with main opcode counts for each circuit
OUTFILE="$ROOT/nargo-info/main_opcodes.json"
echo "{" > "$OUTFILE"
first=1
for circuit in "${CIRCUITS[@]}"; do
    json_file="$ROOT/nargo-info/$circuit.json"
    if [ -f "$json_file" ]; then
        opcodes=$(jq '.programs[0].functions[] | select(.name=="main") | .opcodes' "$json_file")
        if [ -n "$opcodes" ]; then
            if [ $first -eq 0 ]; then
                echo "," >> "$OUTFILE"
            fi
            echo -n "  \"$circuit\": $opcodes" >> "$OUTFILE"
            first=0
        fi
    fi
done
echo "" >> "$OUTFILE"
echo "}" >> "$OUTFILE"
echo "Wrote opcode counts to $OUTFILE"