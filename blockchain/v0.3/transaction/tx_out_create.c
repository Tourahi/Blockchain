#include "transaction.h"

/**
 * tx_out_create - creates a new transaction output structure
 * @amount: is the amount of the transaction
 * @pub: is the public key of the transaction receiver
 * Return: ptr | NULL
 */
tx_out_t *tx_out_create(uint32_t amount, uint8_t const pub[EC_PUB_LEN])
{
	tx_out_t *transaction = calloc(1, sizeof(*transaction));

	if (!transaction)
		return (NULL);
	transaction->amount = amount;
	memcpy(transaction->pub, pub, sizeof(transaction->pub));
	if (!sha256((int8_t const *)transaction,
			sizeof(transaction->amount) + sizeof(transaction->pub),
			transaction->hash))
		return (free(transaction), NULL);
	return (transaction);
}
