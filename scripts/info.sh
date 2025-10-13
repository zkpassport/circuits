# Get the name of the package from the argument
package_name=$1

time nargo compile --force --package $package_name

# Compile the circuit and get the number of the gates
time bb gates --scheme ultra_honk -b ./target/$package_name.json > ./info/$package_name.json