#include "hblk_crypto.h"

/**
 * ec_sign - signs a message with private key
 * @key: ptr to the struct containing key pair
 * @msg: the message to be signed
 * @msglen: length of msg
 * @sig: address to store the signature in
 *
 * Return: pointer to sig buffer or NULL
 */

uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg
	, size_t msglen, sig_t *sig)
{
	unsigned int len;

	if (!key || !msg || !sig)
		return (NULL);

	len = sig->len;

	if (ECDSA_sign(0, msg, msglen, sig->sig, &len,
		(EC_KEY *)key) != 1)
		return (NULL);

	sig->len = len;

	return (sig->sig);
}
