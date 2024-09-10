#!/bin/bash

# Check if the user provided an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <number_of_instances>"
    exit 1
fi

# Get the number of parallel instances to run
n="$1"

# Run n parallel instances of proteusBool
for ((i=1; i<=n; i++)); do
    echo "Starting instance $i"
    proteus_bool &  # Run the instance in the background
done

# Wait for all parallel instances to finish
wait

echo "All $n instances of proteusBool have finished."
