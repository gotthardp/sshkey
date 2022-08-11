#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
ssh-keygen -y -f priv.pem > pub.ssh
ssh-keygen -l -f pub.ssh

./convert priv-ssh priv.pem priv.ssh
ssh-keygen -l -f priv.ssh
ssh-keygen -y -f priv.ssh > pub2.ssh
cmp pub.ssh pub2.ssh

./convert pub-ssh priv.pem pub3.ssh
ssh-keygen -l -f pub3.ssh
cmp pub.ssh pub3.ssh

#rm -f priv.pem priv.ssh pub.ssh pub2.ssh pub3.ssh
