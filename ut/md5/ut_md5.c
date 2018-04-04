#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../src/cryptoc.h"

int main()
{
	int i;
	void* md5 = new(Md5);
	uint8_t digest[16] = {0};
	

	uint8_t* input = "admin";

	MD5_CalculateDigest(md5, input, strlen(input), digest);

	printf("%s md5: is ", input);
	for (i = 0; i < 16; i++)
	{
		 printf("%02x", digest[i]);  
	}
	printf("\n");  

	delete(md5);

	return 0;	
}

