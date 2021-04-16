#include "hblk_crypto.h"

/**
 * ec_load - loads keys from a file
 * @folder: path of the folder the files are stored in
 *
 * Return: EC_KEY key pair
 */
EC_KEY *ec_load(char const *folder)
{
	char file[FILE_LENGTH];
	FILE *fptr = NULL;
	struct stat stbuf;
	EC_KEY *key = NULL;

	if (!folder)
		return (NULL);
	if (stat(folder, &stbuf) == -1)
		return (NULL);

	sprintf(file, "./%s/%s", folder, "key_pub.pem");
	fptr = fopen(file, "r");
	if (!fptr)
		return (NULL);
	if (!PEM_read_EC_PUBKEY(fptr, &key, NULL, NULL))
		return (NULL);
	fclose(fptr);

	sprintf(file, "./%s/%s", folder, "key.pem");
	fptr = fopen(file, "r");
	if (!fptr)
		return (NULL);
	if (!PEM_read_ECPrivateKey(fptr, &key, NULL, NULL))
		return (NULL);

	fclose(fptr);
	return (key);
}
