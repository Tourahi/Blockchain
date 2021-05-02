#include <stdbool.h>
#include "blockchain.h"

/**
 * hash_matches_difficulty - check whether a given hash matches a given difficulty
 * @hash: the hash to check
 * @difficulty: is the minimum difficulty the hash should match
 * Return: 1 | 0
 */

int hash_matches_difficulty(uint8_t const hash[SHA256_DIGEST_LENGTH],
	uint32_t difficulty)
{
	uint8_t *hashPtr = (uint8_t *)hash;
	uint32_t diff = 0;
	int i;
	int indx = 7;
	bool flag = false;

	if (!hash)
		return (0);
	for (; hashPtr + SHA256_DIGEST_LENGTH; hashPtr++)
	{
		for (i = 7; i >= indx; i--)
		{
			if (flag == false)
			{
				if ((*hashPtr >> i) & 1)
				{
					flag = true;
				}
				diff++;
			}
		}
	}
	return (diff >= difficulty);
}
