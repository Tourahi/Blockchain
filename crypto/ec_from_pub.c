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
	EC_GROUP *group;

	if (!pub)
		return (NULL);

	/*
	*	See hblk_crypto.h fo the def of the EC_CURVE nid
	*/
	key = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!key)
		return (NULL);

	group = EC_KEY_get0_group(key);
	if (!group)
		return (NULL);
	/*
	* Create a new point on the curve
	* See : https://www.openssl.org/docs/man1.1.0/man3/EC_POINT_new.html
	*/
	point = EC_POINT_new(group);
	if (!point)
		return (NULL);

	/*
	*	convert from octet to EC_POINT
	*/
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
