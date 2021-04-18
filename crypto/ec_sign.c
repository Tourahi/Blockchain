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
	if (key == 0 || msg == 0 || sig == 0)
		return (NULL);
	if (ECDSA_sign(0, msg, msglen,sig->sig, (void *)&(sig->len),
	(void *)key) != 1)
		return (0);

	return (sig->sig);
}
