/*
 * File       :  ut_rsa.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../src/cryptoc.h"

int main()
{
	b_uint32_t b_x,b_y;
	uint8_t signature[40];
	uint32_t siglen = 0;
 	int valid = 0;

	void* dsa = new(Dsa, DSA_L1024_N160);

	DS_KeyGenerate(dsa);

	uint8_t* msg = "afnjkefnlakjfnakjlfnkajlfhkajcnuihqkjlnaksfjnalksfjlaksjfnclaksjdqkjlafhljkadfna";

	DS_Signature(dsa, msg, strlen(msg), signature, &siglen);

	/* just for test */
	((DSBASE* )dsa)->state = DS_PUBKEYONLY;

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

