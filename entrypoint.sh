#!/bin/bash

mkdir /var/run/sshd
ssh-keygen -A

echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "root:root" | chpasswd

/usr/sbin/sshd

ssh-keygen -t ed25519 -f /root/.ssh/key -q -N ""
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

mkdir data
/usr/local/bin/dvaultd \
    --tag ${TAG} \
    --dvault-private-key-file data/dvault_private_key.txt \
    --dvault-public-key-file data/dvault_public_key.txt \
    --dvault-owner-public-key xUiLzrvBS+k17IzyvHI9LtSJfQj+th1GhzHolagfHbk= \
    --sc-owner-public-key 4ya5w-6ezo4-e23zo-amr2q-uoluc-wpdvs-7qtlp-btgfu-wifhy-3xdck-cqe \
    --sc-device-private-key-file data/sc_private_key.txt \
    --icp-address http://host.docker.internal:7777 \
    --icp-canister-id-path /usr/local/bin/canister_ids.json \
    --ipfs-address http://host.docker.internal:5001 \
    run
