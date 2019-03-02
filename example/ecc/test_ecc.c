/*
 * File       :  ut_ecc.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19    187J3X1    first version
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

    b_ctx_t ctx;

    ECC* ecc = (ECC*)new(Ecc, ECC_CURVE_SECP192K1);

    b_ctx_init(&ctx, ecc->curve->p->len);

    /* pt is the Ecc'G */
    ECC_POINT* pt = (ECC_POINT*)new(Ecc_Point, ecc, ecc->curve->Gx, ecc->curve->Gy);

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

