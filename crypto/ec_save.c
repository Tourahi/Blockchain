
#include "hblk_crypto.h"

/**
 * ec_save - save the key pair into a file
 * @key: key pair
 * @folder: folder path
 *
 * Return: 1 | 0
 */
int ec_save(EC_KEY *key, char const *folder)
{
	FILE *fptr = NULL;
	char file[FILE_LENGTH];
	struct stat stbuf;

	if (!key || !folder)
		return (0);
	if (stat(folder, &stbuf) == -1)
	{
		if (mkdir(folder, FILE_PERMISSION) == -1)
			return (0);
	}

	sprintf(file, "%s/%s", folder, "key.pem");
	fptr = fopen(file, "w");

	if (!fptr)
		return (0);
	if (!PEM_write_ECPrivateKey(fptr, key, NULL, NULL, 0, NULL, NULL))
		return (0);
	fclose(fptr);

	sprintf(file, "%s/%s", folder, "key_pub.pem");
	fptr = fopen(file, "w");

	if (!fptr)
		return (0);
	if (!PEM_write_EC_PUBKEY(fptr, key))
		return (0);

	fclose(fptr);
	return (1);
}
