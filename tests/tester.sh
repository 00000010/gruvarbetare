#!/bin/bash

echo "Running tester..."

for file in ./bazaar/*; do
  python3 ../gruvarbetare.py -f ${file}
done

echo "Complete."

