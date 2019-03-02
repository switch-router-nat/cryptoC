/*
 * File       : ecc.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-06     187J3X1       first version
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../cryptoc.h"
#include "../../base/object.h"
#include "../../bn/bn.h"
#include "ecc.h"

/**************** Defination of Recommened Elliptic Curve Domain Parameters **********************/

static uint32_t pdata_secp192k1[] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFEE37};
static uint32_t adata_secp192k1[] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
static uint32_t bdata_secp192k1[] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000003};
static uint32_t Gxdata_secp192k1[] = {0xDB4FF10E, 0xC057E9AE, 0x26B07D02, 0x80B7F434, 0x1DA5D1B1, 0xEAE06C7D};
static uint32_t Gydata_secp192k1[] = {0x9B2F2F6D, 0x9C5628A7, 0x844163D0, 0x15BE8634, 0x4082AA88, 0xD95E2F9D};
static uint32_t ndata_secp192k1[] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x26F2FC17, 0x0F69466A, 0x74DEFD8D};
static uint32_t hdata_secp192k1[] = {0x00000001};


static b_uint32_t bn_p_secp192k1  = {pdata_secp192k1, sizeof(pdata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_a_secp192k1  = {adata_secp192k1, sizeof(adata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_b_secp192k1  = {bdata_secp192k1, sizeof(bdata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_Gx_secp192k1 = {Gxdata_secp192k1, sizeof(Gxdata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_Gy_secp192k1 = {Gydata_secp192k1, sizeof(Gydata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_n_secp192k1  = {ndata_secp192k1, sizeof(ndata_secp192k1)>>2, 0, 0, 0};
static b_uint32_t bn_h_secp192k1  = {hdata_secp192k1, sizeof(hdata_secp192k1)>>2, 0, 0, 0};


static ecc_curve_t curve_secp192k1 = {&bn_p_secp192k1, 
                                    &bn_a_secp192k1, 
                                    &bn_b_secp192k1, 
                                    &bn_Gx_secp192k1, 
                                    &bn_Gy_secp192k1, 
                                    &bn_n_secp192k1, 
                                    &bn_h_secp192k1};

static ecc_curve_t* ecc_curve_map[]={
    [ECC_CURVE_SECP192K1] = &curve_secp192k1,
};


/**************** End Defination of Recommened Elliptic Curve Domain Parameters **********************/
static void* ecc_point_ctor(void *_self, va_list *app)
{
    ECC_POINT* self = (ECC_POINT*)_self;
    ECC* ecc = va_arg(*app, ECC*);

    b_uint32_t* x = NULL;
    b_uint32_t* y = NULL;

    self->x = b_create(ecc->curve->p->len);
    self->y = b_create(ecc->curve->p->len);

    x = va_arg(*app, b_uint32_t*);
    y = va_arg(*app, b_uint32_t*);

    if (x)
    {
        b_mov(self->x, x);
    }

    if (y)
    {
        b_mov(self->y, y);
    }

    return _self;
}

static void* ecc_point_dtor(void* _self)
{
    ECC_POINT* self = (ECC_POINT*)_self;

    if (self->x)
        b_destroy(self->x);

    if (self->y)
        b_destroy(self->y);

    return _self;
}

static void* ecc_ctor(void *_self, va_list *app)
{
    ECC* self = (ECC*)_self;

    enum ecc_curve_e curve = va_arg(*app, enum ecc_curve_e);

    self->curve = ecc_curve_map[curve];

    return _self;
}

static void* ecc_dtor(void* _self)
{
    ECC* self = (ECC*)_self;

    self->curve = NULL;

    return _self;
}


/*
   pt2 = pt1 + pt1;
*/
static int ecc_doubling(ECC* self, ECC_POINT* pt1, ECC_POINT* pt2, b_ctx_t* ctx)
{
    int rc = -1;
    b_uint32_t* s;
    b_uint32_t* t1;
    b_uint32_t* t2;
    b_uint32_t* t3;
    b_uint32_t* coe; 
    b_uint32_t* prime = self->curve->p;
    b_uint32_t* a = self->curve->a;
    b_ctx_bkp_t bkp;
    b_ctx_save(ctx, &bkp);

    s  = b_ctx_alloc(ctx, prime->len);
    t1 = b_ctx_alloc(ctx, prime->len);
    t2 = b_ctx_alloc(ctx, prime->len);
    t3 = b_ctx_alloc(ctx, prime->len);
    coe = b_ctx_alloc(ctx, prime->len);

    /* t1 = x1^2 mod p */
    b_mulmod(pt1->x, pt1->x, prime, t1, ctx);

    /* coe = 3 */
    b_assign(coe, 0x00000003);

    /* t2 = 3*(x1^2) mod p*/
    b_mulmod(coe, t1, prime, t2, ctx);

    /* t3 = 3*(x1^2) + a mod p */
    b_addmod(t2, a, prime, t3, ctx);

    /* coe = 2 */
    b_assign(coe, 0x00000002);

    /* t1 = 2y1 */
    b_mulmod(coe, pt1->y, prime, t1, ctx);

    /* t2 = 2y1^(-1) */
    rc = b_inverse(t1, prime, t2, ctx);
    if (0 != rc)
    {
        goto err;
    }

    /* s = (3x1^2 + a)/(2y1) mod p */
    b_mulmod(t3, t2, prime, s, ctx);

    /* t1 = s^2 mod p */
    b_mulmod(s, s, prime, t1, ctx);

    /* t2 = x1 + x1 mod p */
    b_addmod(pt1->x, pt1->x, prime, t2, ctx);

    /* x2 = s^2 - x1 - x2 mod p */
    b_submod(t1, t2, prime, pt2->x, ctx);

    /* t1 = x1 - x2 mod p */
    b_submod(pt1->x, pt2->x, prime, t1, ctx);

    /* t2 = s*(x1 - x2) mod p */
    b_mulmod(s, t1, prime, t2, ctx);

    /* y2 = s*(x1 - x2) - y1  mod p */
    b_submod(t2, pt1->y, prime, pt2->y, ctx);

    err:
    b_ctx_restore(ctx, &bkp);

    return 0;
}

/*
	pt3 = pt1 + pt2;
*/
static int ecc_addition(ECC* self, ECC_POINT* pt1, ECC_POINT* pt2, ECC_POINT* pt3, b_ctx_t* ctx)
{
    int rc = -1;
    b_uint32_t* s;
    b_uint32_t* t1;
    b_uint32_t* t2;
    b_uint32_t* t3;
    b_uint32_t* prime = self->curve->p;
    b_ctx_bkp_t bkp;

    b_ctx_save(ctx, &bkp);

    s  = b_ctx_alloc(ctx, prime->len);
    t1 = b_ctx_alloc(ctx, prime->len);
    t2 = b_ctx_alloc(ctx, prime->len);
    t3 = b_ctx_alloc(ctx, prime->len);

    /* t1 = x2 - x1 mod p */
    b_submod(pt2->x, pt1->x, prime, t1, ctx);

    /* t2 = (x2 - x1)^(-1) */
    rc = b_inverse(t1, prime, t2, ctx);
    if (0 != rc)
    {
        goto err;
    }

    /* t1 = y2 - y1 mod p */
    b_submod(pt2->y, pt1->y, prime, t1, ctx);

    /* s = (y2-y1)*(x2-x1)^-1 mod p */
    b_mulmod(t1, t2, prime, s, ctx);

    /* t1 = s^2 mod p */
    b_mulmod(s, s, prime, t1, ctx);

    /* t2 = x1 + x2 mod p */
    b_addmod(pt1->x, pt2->x, prime, t2, ctx);

    /* x3 = s^2 - x1 - x2 mod p */
    b_submod(t1, t2, prime, pt3->x, ctx);

    /* t1 = x1 - x3 mod p */
    b_submod(pt1->x, pt3->x, prime, t1, ctx);

    /* t2 = s*(x1 - x3) mod p */
    b_mulmod(s, t1, prime, t2, ctx);

    /* y3 = s*(x1 - x3) - y1  mod p */
    b_submod(t2, pt1->y, prime, pt3->y, ctx);

err:
    b_ctx_restore(ctx, &bkp);

    return rc;
}

/* Check whether @pt is on the @self->curve: y^2 = x^3 + ax + b mod p
 * return 1 -- on the curve 
 *        0 -- not on the curve 
*/
static int ecc_validation(ECC* self, ECC_POINT* pt, b_ctx_t* ctx)
{
    int rc = 0;
    b_uint32_t* prime = self->curve->p;
    b_uint32_t* t1;
    b_uint32_t* t2;
    b_uint32_t* t3;
    b_uint32_t* coe; 
    b_ctx_bkp_t bkp;
    b_ctx_save(ctx, &bkp);

    t1 = b_ctx_alloc(ctx, prime->len);
    t2 = b_ctx_alloc(ctx, prime->len);
    t3 = b_ctx_alloc(ctx, prime->len);
    coe = b_ctx_alloc(ctx, prime->len);

    /* coe = 3 */
    b_assign(coe, 0x00000003);

    /* t1 = x^3 */
    b_expmod(pt->x, coe, prime, t1, ctx);

    /* t2 = ax */
    b_mulmod(pt->x, self->curve->a, prime, t2, ctx);

    /* t3 = t1 + t2 = x^3 + ax */
    b_addmod(t1, t2, prime, t3, ctx);

    /* t1 = t3+ b = x^3 + ax + b */
    b_addmod(t3, self->curve->b, prime, t1, ctx);

    /* t2 = y^2  */
    b_mulmod(pt->y, pt->y, prime, t2, ctx);

    if (b_cmp(t1, t2) == 0)
    {
        rc = 1;
    }

    b_ctx_restore(ctx, &bkp);

    return rc;
}


/* assign pt1 = pt2 */
static inline void ecc_pointassign(ECC_POINT* pt1, ECC_POINT* pt2)
{
    b_mov(pt1->x, pt2->x);
    b_mov(pt1->y, pt2->y);

    return;
}

/*
   Double-and-Add Algorithm for Point Multiplication
   @pt2 = @d * @pt1
*/
int ecc_multiplication(void* _self, b_uint32_t* d, void* _pt1, void* _pt2, b_ctx_t* ctx)
{
    int rc = -1;
    int top;
    int topbit;
    ECC* self = (ECC*)_self;
    ECC_POINT* pt1 = (ECC_POINT* )_pt1;
    ECC_POINT* pt2 = (ECC_POINT* )_pt2;
    ECC_POINT* ptmp1 = (ECC_POINT* )new(Ecc_Point, self, NULL, NULL);
    ECC_POINT* ptmp2 = (ECC_POINT* )new(Ecc_Point, self, NULL, NULL);
    b_uint32_t* prime = self->curve->p;

    b_ctx_bkp_t bkp;
    b_ctx_save(ctx, &bkp);

    /* Initialization: t2 = pt1 */
    ecc_pointassign(ptmp2, pt1);

    top = b_valid_top(d);
    if (top == d->len)
    {
        /* d == 0 */
        goto err;
    }

    topbit = b_valid_topbit(d);

    for (int i= top*32 + topbit + 1; i<(d->len)*32; ++i)
    {
        /* t1 = t2 + t2 */
        rc = ecc_doubling(self, ptmp2, ptmp1, ctx);

        if (d->data[i/32] & (0x80000000 >> (i%32)))
        {
            /* t2 = t1 + pt1 */
            rc |= ecc_addition(self, ptmp1, pt1, ptmp2, ctx);
        }
        else
        {
            ecc_pointassign(ptmp2, ptmp1);
        }

        if (0 != rc)
        {
            goto err;
        }
    }

    ecc_pointassign(pt2, ptmp2);

    err:
    delete((void*)ptmp1);
    delete((void*)ptmp2);
    b_ctx_restore(ctx, &bkp);

    return rc;
}

static const OBJECT _Ecc_Point = {
    sizeof(ECC_POINT),
    NULL,
    ecc_point_ctor, 
    ecc_point_dtor,	
};

const void* Ecc_Point = &_Ecc_Point;

static const OBJECT _Ecc = {
    sizeof(ECC),
    NULL,
    ecc_ctor, 
    ecc_dtor,	
};

const void* Ecc = &_Ecc;
