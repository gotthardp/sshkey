# Save OpenSSL EVP_PKEY as OpenSSH key

This library enables developers to export OpenSSH keys from the
[EVP_PKEY](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY.html)
structure.

For now only [RSA](https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-RSA.html)
is supported.

With OpenSSL you are using `EVP_PKEY` structures that can be saved
in a PEM format:
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQb+ekt5JUQAJ5
3C39pU2oD7RaiZ/eb7a9FafWDnDKhh7SLpXQZx/ZZmBtl/M9gF19ImzQWC2eeFyh
...
0b+261x92+AApCHbyvv9DxuTrwnGBcZs8U7sDiEHCd+QGxDe1LEQ3rEQkXGz3sIZ
ZDx9nTUKCPC/1KQhlhtmeKjX
-----END PRIVATE KEY-----
```

The `sshkey_store_priv()` function saves the `EVP_PKEY` as an OpenSSH private key:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
c2gtcnNhAAAAAwEAAQAAAQEA0G/npLeSVEACedwt/aVNqA+0Womf3m+2vRWn1g5w
...
/HFOQTkwvTo9rAGevu4TRSCi4yvOkiTaj6Yjf3dqK9eTUw+hC1lajC4N2BehHimZ
snbyvx/9B1soDia6xZqGhDWhYuzc0mkdAAAAAAEC
-----END OPENSSH PRIVATE KEY-----
```

The `sshkey_store_pub()` function saves the `EVP_PKEY` as an OpenSSH public key:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQ...wTh28zLd3lYnByN+qLXEt5Nn7P1pX1A1MReCbb2SKrsKXxN
```

The OpenSSH private key binary format is nicely described in
[this blog](https://dnaeon.github.io/openssh-private-key-binary-format/).

## Build

First, you need to install OpenSSL 3.0.

```bash
mkdir build; cd build
cmake .. -DENABLE_TESTS=YES -DCMAKE_BUILD_TYPE=Debug
make
```
