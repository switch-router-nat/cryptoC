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
	
	void* dsa = new(Dsa, DSA_L1024_N160);

	DS_KeyGenerate(dsa);

	uint8_t* msg = "afnjkefnlakjfnakjlfnkajlfhkajcnuihqkjlnaksfjnalksfjlaksjfnclaksjdqkjlafhljkadfna";

	DS_Signature(dsa, msg, strlen(msg), NULL, 0);

	delete(dsa);

	return 0;	
}

