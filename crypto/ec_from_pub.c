#include "hblk_crypto.h"

/**
 * ec_from_pub - generates EC_KEY from pub key
 * @pub: the pub key in thebuffer
 *
 * Return: The generated EC_KEY struct
 */
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN])
{
	EC_KEY *key;
	EC_POINT *point;
	const EC_GROUP *group;

	if (!pub)
		return (NULL);

	key = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!key)
		return (NULL);

	group = EC_KEY_get0_group(key);

	point = EC_POINT_new(group);
	if (!point)
		return (NULL);

	int isConverted = EC_POINT_oct2point(group, point, pub, EC_PUB_LEN, NULL);
	int isPublicKeySet = EC_KEY_set_public_key(key, point);

	if (!isConverted || !isPublicKeySet)
	{
		EC_KEY_free(key);
		EC_POINT_free(point);
		return (NULL);
	}
	EC_POINT_free(point);
	return (key);
}
