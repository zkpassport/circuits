# Get the name of the circuit from the argument
package_name=$1
oracle_hash=${2:-"poseidon2"}

# Compile the circuit and get the number of the gates
nargo compile --force --package $package_name && bb write_vk --scheme ultra_honk --honk_recursion 1 --output_format bytes_and_fields -b ./target/$package_name.json -o ./vkeys/${package_name} --oracle_hash ${oracle_hash}