#include <sodium.h>
#include <string.h>

int generate_ssh_keypair(char *pubkey_b64, size_t pubkey_len, char *privkey_b64, size_t privkey_len) {
    if (sodium_init() < 0) return 0;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    return sodium_bin2base64(pubkey_b64, pubkey_len, pk, sizeof(pk), sodium_base64_VARIANT_ORIGINAL) != NULL &&sodium_bin2base64(privkey_b64, privkey_len, sk, sizeof(sk), sodium_base64_VARIANT_ORIGINAL) != NULL;
}