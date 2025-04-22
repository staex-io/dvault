#!/bin/bash

/usr/sbin/sshd

/usr/local/bin/dvaultd \
    --dvault-private-key-file data/dvault_private_key.txt \
    --dvault-public-key-file data/dvault_public_key.txt \
    --dvault-owner-public-key xUiLzrvBS+k17IzyvHI9LtSJfQj+th1GhzHolagfHbk= \
    --sc-owner-public-key 4ya5w-6ezo4-e23zo-amr2q-uoluc-wpdvs-7qtlp-btgfu-wifhy-3xdck-cqe \
    --sc-device-private-key-file data/sc_private_key.txt \
    --tag tag__ \
    --icp-address http://host.docker.internal:7777 \
    --icp-canister-id-path /usr/local/bin/canister_ids.json \
    --ipfs-address http://host.docker.internal:5001 \
    run
