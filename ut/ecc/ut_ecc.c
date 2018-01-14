/*
 * File       :  ut_ecc.c
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

	b_ctx_t ctx;
	
	void* ecc = new(Ecc, ECC_CURVE_SECP192K1);

	b_ctx_init(&ctx, ((ECC*)ecc)->curve->p->len);

	/* pt is the Ecc'G */
	void* pt = new(Ecc_Point, ecc, ((ECC*)ecc)->curve->Gx, ((ECC*)ecc)->curve->Gy);

	b_uint32_t* d = b_create(1);
	b_assign(d, 0x00000003);

	void* pt2 = new(Ecc_Point, ecc, NULL, NULL);
	int rc = ecc_multiplication(ecc, d, pt, pt2, &ctx);

	delete(pt);
	delete(pt2);
	delete(ecc);

	b_ctx_fini(&ctx);

	return 0;	
}

