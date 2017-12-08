/*
 * File       :  ecc.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-12-04     QshLyc       first version
 */

#ifndef _CRYPTOC_ECC_H_
#define _CRYPTOC_ECC_H_

#ifdef __cplusplus
extern "C" {
#endif


enum ecc_curve_e{
	ECC_CURVE_SECP192K1 = 0,
};

typedef struct{
	b_uint32_t* p;    /* prime */     
	b_uint32_t* a;   
	b_uint32_t* b;   
	b_uint32_t* Gx; 	
	b_uint32_t* Gy;	
	b_uint32_t* n;	
	b_uint32_t* h;	
}ecc_curve_t;

extern const void* Ecc_Point;

typedef struct{
	const void* object;
	b_uint32_t* x;
	b_uint32_t* y;
}ECC_POINT;

extern const void* Ecc;

typedef struct{
	const void* object;
	ecc_curve_t* curve;
}ECC;


int ecc_validation(void* _self, void* _pt, b_ctx_t* ctx);
int ecc_doubling(ECC* self, ECC_POINT* pt1, ECC_POINT* pt2, b_ctx_t* ctx);
int ecc_addition(ECC* self, ECC_POINT* pt1, ECC_POINT* pt2, ECC_POINT* pt3, b_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
