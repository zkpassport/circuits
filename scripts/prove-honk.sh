# Get the name of the package from the argument
package_name=$1

# Execute the circuit to generate a witness
nargo execute --package $package_name ${package_name}_witness

mkdir -p ./proofs/${package_name}_honk

# Generate a Honk proof for the circuit with the witness generated just before
time bb prove --scheme ultra_honk -b ./target/$package_name.json -w ./target/${package_name}_witness.gz -o ./proofs/${package_name}_honk