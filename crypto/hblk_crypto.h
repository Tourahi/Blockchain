#ifndef _HBLK_CRYPTO_H_
#define _HBLK_CRYPTO_H_

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <sys/stat.h>

#define EC_CURVE NID_secp256k1

#define EC_PUB_LEN 65
#define SIG_MAX_LEN 72

#define PRI_FILENAME "key.pem"
#define PUB_FILENAME "key_pub.pem"

/*
*	save file conf
*/
#define FILE_LENGTH  512
#define FILE_PERMISSION  0700

/**
 * struct sig_s - EC Signature structure
 *
 * @sig: Signature buffer. The whole space may not be used
 * @len: Actual signature size.
 */
typedef struct sig_s
{
	uint8_t sig[SIG_MAX_LEN];
	uint8_t len;
} sig_t;

EC_KEY *ec_create(void);
uint8_t *sha256(int8_t const *s, size_t len, uint8_t di[SHA256_DIGEST_LENGTH]);
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]);
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]);

/*
*	save an existing EC key pair on the disk.
*/
int ec_save(EC_KEY *key, char const *folder);

/*
*	 loads an EC key pair from the disk.
*/
EC_KEY *ec_load(char const *folder);

/*
*	 signs a given set of bytes, using a given EC_KEY private key
*/
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg
	, size_t msglen, sig_t *sig);

int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen
	, sig_t const *sig);

#endif

