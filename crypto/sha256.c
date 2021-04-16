
#include "hblk_crypto.h"

/**
 * sha256 - computes the hash of a sequence of bytes
 * @s : the sequence of bytes to be hashed
 * @len : the number of bytes to hash in s
 * @di : the stored hash
 *
 * Return: A pointer to digest
 */
uint8_t *sha256(int8_t const *s, size_t len, uint8_t di[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX c;

	if (di == NULL)
	{
		return (NULL);
	}

	SHA256_Init(&c);
	SHA256_Update(&c, s, len);
	SHA256_Final(di, &c);

	return (di);
}
