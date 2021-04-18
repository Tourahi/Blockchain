#include "blockchain.h"

header_t set_header(header_t header, blockchain_t const *blockchain)
{
	memcpy(header.hblk_magic, HBLK_MAGIC, HBLK_MAGIC_LEN);
	memcpy(header.hblk_version, HBLK_VERSION, HBLK_VERSION_LEN);
	header.hblk_endian = _get_endianness();
	header.hblk_blocks = llist_size(blockchain->chain);
	return header;
}

int blockchain_serialize(blockchain_t const *blockchain, char const *path)
{
	header_t h;
	FILE *fp = NULL;
	block_t *b = NULL;
	int i = LOOP_START;

	if (!blockchain || !path)
		return (-1);

	h = set_header(h, blockchain);
	fp = fopen(path, "w");
	if (fp == NULL)
		return (-1);
	fwrite(&h, sizeof(h), 1, fp);

	for(i = 0; i < h.hblk_blocks; i++)
	{
		b = llist_get_node_at(blockchain->chain, i);
		if (!b)
		{
			fclose(fp);
			return (-1);
		}
		fwrite((void *)&b->info, sizeof(b->info), 1, fp);
		fwrite((void *)&b->data.len, sizeof(b->data.len), 1, fp);
		fwrite(b->data.buffer, b->data.len, 1, fp);
		fwrite((void *)&b->hash, sizeof(b->hash), 1, fp);
	}
	fclose(fp);
	return (0);
}
