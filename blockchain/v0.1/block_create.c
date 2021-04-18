#include "blockchain.h"




block_t *block_create(block_t const *prev,
					int8_t const *data, uint32_t data_len)
{
	block_t *newB = calloc(1, sizeof(*newB));
	uint32_t maxL = B_DATA_MAX;

	if (!newB)
		return (NULL);

	if (data_len < B_DATA_MAX)
		maxL = data_len;

	memcpy(&(newB->data.buffer), data, maxL);
	newB->data.len = maxL;
	newB->info.index = prev->info.index + 1;
	newB->info.timestamp = (uint64_t)time(NULL);

	memcpy(&(newB->info.prev_hash), prev->hash, SHA256_DIGEST_LENGTH);

	return (newB);
}
