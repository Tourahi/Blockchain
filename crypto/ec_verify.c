#include "hblk_crypto.h"

/**
 * ec_verify - verifies a message
 * @key: pointer to struct containing the key pair
 * @msg: the message
 * @msglen: length of msg
 * @sig: address to store signature
 *
 * Return: 1 | 0
 */

int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen,
	sig_t const *sig)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if (!msg || !key || !sig)
		return (0);
	if (!EC_KEY_check_key(key))
		return (0);
	if (!SHA256(msg, msglen, hash))
		return (0);
	if (!ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig->sig, sig->len,
			  (EC_KEY *)key))
		return (0);

	return (1);
}
