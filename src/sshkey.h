/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/evp.h>

/* Store public key in the OpenSSL format */
int sshkey_store_pub(const EVP_PKEY *pkey, FILE *fp);

/* Store public key in the SSH2 format */
int sshkey_store_pub2(const EVP_PKEY *pkey, FILE *fp);

/* Store private key in the OpenSSL format */
int sshkey_store_priv(const EVP_PKEY *pkey, FILE *fp);
