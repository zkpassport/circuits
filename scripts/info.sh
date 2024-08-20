# Get the name of the package from the argument
package_name=$1

# Compile the circuit and get the number of the gates
nargo compile --force --package $package_name && bb gates -b ./target/$package_name.json > ./info/$package_name.json