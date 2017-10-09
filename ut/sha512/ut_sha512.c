#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../src/cryptoc.h"

int main()
{
	uint64_t size;
	uint8_t  digest[64];
	uint8_t* data;
	uint8_t* data_str = "";
	uint8_t i;

	data = (uint8_t*)malloc(strlen(data_str));
	memcpy(data ,data_str, strlen(data_str));

	void* sha512 = new(Sha512);

	size = strlen(data_str) << 3;

	SHA_CalculateDigest(sha512, data, size, digest);


	for (i = 0; i < 64; i++)
	{
		printf("0x%x ", digest[i]);
	}

	delete(sha512);

	return 0;	
}

