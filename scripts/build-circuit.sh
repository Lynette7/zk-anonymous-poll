#!/bin/bash
# Script to build the Noir circuit and generate proofs

set -e

echo "🔧 Building Building ZK Anonymous Poll Noir Circuit..."

# Navigate to circuits directory
cd ..
cd circuits

# Check if Noir project exists
if [ ! -f "Nargo.toml" ]; then
    echo "❌ Nargo.toml not found. Please run setup.sh first."
    exit 1
fi

# generate a Prover.toml file
echo "🔧 Generating Prover.toml"
nargo execute 

# Compile and execute the circuit
echo "📦 Compiling and executing circuit..."
nargo execute

if [ $? -eq 0 ]; then
    echo "✅ Circuit compiled successfully!"
else
    echo "❌ Circuit compilation or execution failed!"
    exit 1
fi

# Run tests
echo "🧪 Running circuit tests..."
nargo test

if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed!"
    exit 1
fi

# Generate proof with test inputs
echo "🔍 Generating proof with test inputs..."
bb prove -b ./target/circuits.json -w ./target/circuits.gz -o ./target

if [ $? -eq 0 ]; then
    echo "✅ Proof generated successfully!"
    echo "📂 Proof saved to: circuits/target/proof"
else
    echo "❌ Proof generation failed!"
    exit 1
fi

# Generate the verification key and save to ./target/vk
echo "🔐 Generating verification key..."
bb write_vk -b ./target/circuits.json -o ./target

# Verify the proof
echo "🔐 Verifying proof..."
bb verify -k ./target/vk -p ./target/proof -i ./target/public_inputs

if [ $? -eq 0 ]; then
    echo "✅ Proof verified successfully!"
else
    echo "❌ Proof verification failed!"
    exit 1
fi

echo ""
echo "🎉 Circuit build and test complete!"
echo "📊 Circuit statistics:"
nargo info

cd ..
