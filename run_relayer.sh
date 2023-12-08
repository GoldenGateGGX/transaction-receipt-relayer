#!/bin/bash

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <helios_config> <secret_config> <executable> [args...]"
  exit 1
fi

# The URL to query for checkpoint
URL="https://beaconstate-sepolia.chainsafe.io/checkpointz/v1/status"

HELIOS_CONFIG="$1"
SECRET_CONFIG="$2"
EXECUTABLE="$3"
shift 3

FINALIZED_ROOT=$(curl -s $URL | jq -r '.data.finality.finalized.root')

# Check if the FINALIZED_ROOT is empty or not
if [ -z "$FINALIZED_ROOT" ]; then
    echo "No data found"
else
    # Replace the init_block_root value in the config file
    sed -i "s|checkpoint.*=.*|checkpoint=\"$FINALIZED_ROOT\"|" "$HELIOS_CONFIG"
    echo "Updated init_block_root to $FINALIZED_ROOT in $HELIOS_CONFIG"
fi

# Put secret mnemonic from the environment variable into the secret config file
echo "Putting secret mnemonic from the environment variable into the secret config file"
sed -i "s|phrase.*=.*|phrase=\"$MNEMONIC\"|" "$SECRET_CONFIG"
# Replace infura key in the helios config file
echo "Replacing infura key in $HELIOS_CONFIG"
sed -i "s|{INFURA_KEY}|$INFURA_KEY|" "$HELIOS_CONFIG"

# Execute the provided executable with remaining arguments
"$EXECUTABLE" "$@"