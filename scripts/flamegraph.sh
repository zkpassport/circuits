# Get the name of the package from the argument
package_name=$1

# Compile the circuit and get the number of the gates
nargo compile --force --package $package_name

# Generate the flamegraph
mkdir -p ./flamegraphs/$package_name
noir-profiler gates --artifact-path ./target/$package_name.json --backend-path $HOME/.bb/bb --output ./flamegraphs/$package_name -g "gates" --include_gates_per_opcode
noir-profiler opcodes --artifact-path ./target/$package_name.json --output ./flamegraphs/$package_name
open -a "Google Chrome" ./flamegraphs/$package_name/main_acir_opcodes.svg
open -a "Google Chrome" ./flamegraphs/$package_name/main_gates.svg
