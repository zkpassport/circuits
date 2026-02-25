# Get the name of the circuit from the argument
package_name=$1
verifier_target=${2:-"noir-recursive"}

# Compile the circuit and generate the verification key
nargo compile --force --package $package_name && bb write_vk -t ${verifier_target} -b ./target/$package_name.json -o ./vkeys/${package_name}