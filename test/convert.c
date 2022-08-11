/* SPDX-License-Identifier: BSD-3-Clause */

#include <sys/stat.h>
#include <openssl/pem.h>
#include "sshkey.h"

int main(int argc, char *argv[])
{
    int res = 1;
    FILE *inf = NULL, *ouf = NULL;
    EVP_PKEY *pkey = NULL;

    if (argc != 4) {
        fprintf(stderr, "%s <cmd> <in-file> <out-file>\n", argv[0]);
        fprintf(stderr, "  pub-ssh   Convert PEM to OpenSSH public key.\n");
        fprintf(stderr, "  pub-ssh2  Convert PEM to SSH2 public key.\n");
        fprintf(stderr, "  priv-ssh  Convert PEM to OpenSSH private key.\n");
        exit(1);
    }

    if ((inf = fopen(argv[2], "r")) == NULL) {
        perror("cannot open");
        goto final;
    }

    pkey = PEM_read_PrivateKey(inf, NULL, NULL, NULL);

    if ((ouf = fopen(argv[3], "w")) == NULL) {
        perror("cannot open");
        goto final;
    }

    if (strcmp(argv[1], "pub-ssh") == 0) {
        res = sshkey_store_pub(pkey, ouf);
    } else if (strcmp(argv[1], "pub-ssh2") == 0) {
        res = sshkey_store_pub2(pkey, ouf);
    } else if (strcmp(argv[1], "priv-ssh") == 0) {
        // openssh checks key permissions
        fchmod(fileno(ouf), 0600);
        res = sshkey_store_priv(pkey, ouf);
    } else {
        fprintf(stderr, "Unknown command\n");
        goto final;
    }

    if (res)
        perror("cannot save");
final:
    EVP_PKEY_free(pkey);
    fclose(inf);
    fclose(ouf);
    return res;
}
