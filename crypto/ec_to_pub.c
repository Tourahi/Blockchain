#include "hblk_crypto.h"

/**
 * ec_to_pub - extracts the public key from EC_KEY struct
 * @key : pointer to the EC_KEY struct
 * @pub : address of the buffer to populate
 *
 * Return: A pointer to digest
 */
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN])
{
	/**
	*The public key is an EC_POINT on the curve calculated by
	multiplying the generator for the curve by the private key
	*/
	const EC_POINT *point = NULL;
	const EC_GROUP *group = NULL;

	if (!key || !pub)
		return (NULL);

	/**
	*Get the EC_POINT public key for the key
	*Get the EC_GROUP object for the key
	*/
	point = EC_KEY_get0_public_key(key);
	group = EC_KEY_get0_group(key);

	if (!point || !group)
		return (NULL);

	/**
	*Convert from EC_POINT to octet
	*EC_POINT_point2oct must be supplied with a buffer long enough
	 to store the octet string.
	*/
	if (!EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pub
		, EC_PUB_LEN
		, NULL))
		return (NULL);

	return (pub);
}
