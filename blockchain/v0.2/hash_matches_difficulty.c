#include <stdbool.h>
#include "blockchain.h"

/**
 * diff - number of leading bits in the hash
 * @hash: hash buffer
 *
 * Return: difficulty
 */
uint32_t diff(uint8_t const hash[SHA256_DIGEST_LENGTH])
{
	uint8_t *p = (uint8_t *)hash;
	uint32_t diff = 0;
	int i;

	for (; p < hash + SHA256_DIGEST_LENGTH; p++)
	{
		for (i = 7; i >= 0; i--)
		{
			if ((*p >> i) & 1)
				return (diff);
			diff++;
		}
	}
	return (diff);
}

/**
 * hash_matches_difficulty - check whether a given hash matches a difficulty
 * @hash: the hash to check
 * @difficulty: is the minimum difficulty the hash should match
 *
 * Return: 1 | 0
 */

int hash_matches_difficulty(uint8_t const hash[SHA256_DIGEST_LENGTH],
	uint32_t difficulty)
{
	if (!hash)
		return (0);
	return (diff(hash) >= difficulty);
}
