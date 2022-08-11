/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <arpa/inet.h>
#include <openssl/core_names.h>
#include "sshkey.h"

#define FORMAT_RSA "ssh-rsa"
#define AUTH_MAGIC "openssh-key-v1"

static int
uint2mpi(uint32_t num, unsigned char *out)
{
    *(uint32_t*)out = htonl(num);
    return sizeof(uint32_t);
}

static int
bytes2mpi(const char *string, int len, unsigned char *out)
{
    // string without the trailing '\0'
    memcpy(out, string, len);
    return len;
}

static int
str2mpi(const char *string, unsigned char *out)
{
    int len = sizeof(uint32_t) + strlen(string);
    if (out != NULL) {
        out += uint2mpi(strlen(string), out);
        bytes2mpi(string, strlen(string), out);
    }
    return len;
}

static int
get_rsa_pubkey(const EVP_PKEY *pkey, unsigned char **buf)
{
    BIGNUM *e = NULL, *n = NULL;
    unsigned char *pos;
    int len, res = -1;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n))
        goto final;

    // RFC 4253, Section 6.6
    //  string  "ssh-rsa"
    //  mpint   e
    //  mpint   n
    len = str2mpi(FORMAT_RSA, NULL)
        + BN_bn2mpi(e, NULL)
        + BN_bn2mpi(n, NULL);

    pos = *buf = malloc(len);
    if (!pos)
        goto final;

    pos += str2mpi(FORMAT_RSA, pos);
    pos += BN_bn2mpi(e, pos);
    pos += BN_bn2mpi(n, pos);
    res = pos - *buf;
final:
    BN_free(e);
    BN_free(n);
    return res;
}

static int
get_rsa_privlist(const EVP_PKEY *pkey, unsigned char **buf, int bsize)
{
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *iqmp = NULL;
    uint32_t checkint;
    unsigned char *pos;
    int len, padlen, i, res = 0;

    // see RFC 8017
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q)
            || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp))
        goto final;

    // this doesn't have to be trully random
    checkint = rand();

    // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    // Section 3
    //  uint32  checkint
    //  uint32  checkint
    //  byte[]  privatekey1
    //  string  comment1
    //  byte    1
    //  byte    2
    //  byte    3
    //  ...
    //  byte    padlen % 255

    // where the RSA privatekey1
    // https://dnaeon.github.io/openssh-private-key-binary-format/
    //  string  "ssh-rsa"
    //  mpint   n    (modulus)
    //  mpint   e    (public exponent)
    //  mpint   d    (private exponent)
    //  mpint   iqmp (inverse of q mod p)
    //  mpint   p    (prime 1)
    //  mpint   q    (prime 2)
    len = 2*sizeof(uint32_t)
        + str2mpi(FORMAT_RSA, NULL)
        + BN_bn2mpi(n, NULL)
        + BN_bn2mpi(e, NULL)
        + BN_bn2mpi(d, NULL)
        + BN_bn2mpi(iqmp, NULL)
        + BN_bn2mpi(p, NULL)
        + BN_bn2mpi(q, NULL)
        + str2mpi("", NULL);

    if ((padlen = (-len) % bsize) < 0)
        padlen += bsize;

    pos = *buf = malloc(len+padlen);
    if (!pos)
        goto final;

    pos += uint2mpi(checkint, pos);
    pos += uint2mpi(checkint, pos);
    pos += str2mpi(FORMAT_RSA, pos);
    pos += BN_bn2mpi(n, pos);
    pos += BN_bn2mpi(e, pos);
    pos += BN_bn2mpi(d, pos);
    pos += BN_bn2mpi(iqmp, pos);
    pos += BN_bn2mpi(p, pos);
    pos += BN_bn2mpi(q, pos);
    pos += str2mpi("", pos);
    for (i = 1; i <= padlen; i++)
        *(pos++) = i % 255;
    res = pos - *buf;
final:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(iqmp);
    return res;
}

static int
save_base64_block(const unsigned char *in, int inl, FILE *fp)
{
    EVP_ENCODE_CTX *enctx = NULL;
    int outl;
    unsigned char *out;

    enctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(enctx);

    out = malloc(65 * (inl / 48) + 1);
    EVP_EncodeUpdate(enctx, out, &outl, in, inl);
    if (outl > 0)
        fputs(out, fp);

    EVP_EncodeFinal(enctx, out, &outl);
    if (outl > 0)
        fputs(out, fp);

    free(out);
    EVP_ENCODE_CTX_free(enctx);
    return 0;
}

static int
sshkey_get_pubkey(const EVP_PKEY *pkey, unsigned char **buf)
{
    switch (EVP_PKEY_get_id(pkey)) {
    case EVP_PKEY_RSA:
        return get_rsa_pubkey(pkey, buf);
    default:
        return 0;
    }
}

int
sshkey_store_pub(const EVP_PKEY *pkey, FILE *fp)
{
    unsigned char *pubuff, *encbuff;
    int publen, enclen;

    publen = sshkey_get_pubkey(pkey, &pubuff);

    // save as one line
    encbuff = malloc(4 * ((publen + 2) / 3) + 1);
    enclen = EVP_EncodeBlock(encbuff, pubuff, publen);

    fprintf(fp, "%s %s\n", FORMAT_RSA, encbuff);
    free(encbuff);
    free(pubuff);
    return 0;
}

int
sshkey_store_pub2(const EVP_PKEY *pkey, FILE *fp)
{
    unsigned char *pubuff;
    int publen;

    publen = sshkey_get_pubkey(pkey, &pubuff);

    // save as a block
    fprintf(fp, "---- BEGIN SSH2 PUBLIC KEY ----\n");
    save_base64_block(pubuff, publen, fp);
    free(pubuff);
    fprintf(fp, "---- END SSH2 PUBLIC KEY ----\n");
    return 0;
}

static int
sshkey_get_privlist(const EVP_PKEY *pkey, unsigned char **buf, int bsize)
{
    switch (EVP_PKEY_get_id(pkey)) {
    case EVP_PKEY_RSA:
        return get_rsa_privlist(pkey, buf, bsize);
    default:
        return 0;
    }
}

int
sshkey_store_priv(const EVP_PKEY *pkey, FILE *fp)
{
    unsigned char *buff, *pos, *pubuff, *pribuff;
    int len, publen, prilen;

    if (!(publen = sshkey_get_pubkey(pkey, &pubuff)))
        return 0;

    prilen = sshkey_get_privlist(pkey, &pribuff, 8);

    // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    // Section 1
    //  byte[]  "openssh-key-v1"
    //  string  ciphername
    //  string  kdfname
    //  string  kdfoptions
    //  uint32  number of keys N
    //  string  publickey1
    //  string  encrypted, padded list of private keys
    len = strlen(AUTH_MAGIC)+1
        + str2mpi("none", NULL)
        + str2mpi("none", NULL)
        + str2mpi("", NULL)
        + sizeof(uint32_t)
        + sizeof(uint32_t) + publen
        + sizeof(uint32_t) + prilen;

    pos = buff = malloc(len);
    // including the final \0
    pos += bytes2mpi(AUTH_MAGIC, strlen(AUTH_MAGIC)+1, pos);
    pos += str2mpi("none", pos);
    pos += str2mpi("none", pos);
    pos += str2mpi("", pos);
    pos += uint2mpi(1, pos);
    pos += uint2mpi(publen, pos);
    pos += bytes2mpi(pubuff, publen, pos);
    pos += uint2mpi(prilen, pos);
    pos += bytes2mpi(pribuff, prilen, pos);

    free(pubuff);
    free(pribuff);

    // save as a block
    fprintf(fp, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    save_base64_block(buff, len, fp);
    free(buff);
    fprintf(fp, "-----END OPENSSH PRIVATE KEY-----\n");
    return 0;
}
