#!/bin/bash

echo "SOC Authentication Attack Simulation"
echo "-------------------------------------"

for i in {1..8}
do
    echo "Attempt $i"

    ssh -o ConnectTimeout=3 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        root@localhost

done

echo "Authentication test complete."