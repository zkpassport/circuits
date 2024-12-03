# Get the name of the package from the argument
package_name=$1

# Compile the circuit and get the number of the gates
nargo compile --force --package $package_name

# Generate the flamegraph
noir-profiler gates-flamegraph --artifact-path ./target/$package_name.json --backend-path $HOME/.bb/bb --output ./flamegraphs/$package_name.svg
noir-profiler opcodes-flamegraph --artifact-path ./target/$package_name.json --output ./flamegraphs/${package_name}_opcodes.svg