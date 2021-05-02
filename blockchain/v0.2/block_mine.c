#include "blockchain.h"


/**
 * block_mine - mines a Block in order to insert it in the Blockchain
 * @block: points to the Block to be mined
 */
void block_mine(block_t *block)
{
	uint64_t nc = 0;

	do {
		block->info.nonce = nc;
		block_hash(block, block->hash);
		nc++;
	} while (!hash_matches_difficulty(block->hash, block->info.difficulty));
}
