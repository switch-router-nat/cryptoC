/*
 * File       :  ut_rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     187J3X1       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <cryptoc.h>


int main()
{
	b_uint32_t b_x,b_y;
	uint8_t signature[40];
	uint32_t siglen = 0;
 	int valid = 0;

	void* dsa = (void*)new(Dsa, DSA_L1024_N160);

	DS_KeyGenerate(dsa);

	uint8_t* msg = "afnjkefnlakjfnakjlfnkajlfhkajcnuihqkjlnaksfjnalksfjlaksjfnclaksjdqkjlafhljkadfna";

	DS_Signature(dsa, msg, strlen(msg), signature, &siglen);

	valid = DS_Verify(dsa, msg, strlen(msg), signature, siglen);
	if (valid == 1)
	{
		printf("valid signature!\n");
	}
	else {
		printf("invalid signature!\n");
	}

	delete(dsa);

	return 0;	
}

