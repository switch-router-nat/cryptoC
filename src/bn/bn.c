/*
 * File       :  bn.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     QshLyc       first version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "bn.h"

#define BN_MIN(a,b)  ((a)<(b)?(a):(b))
#define BN_MAX(a,b)  ((a)<(b)?(b):(a))

void b_zero(b_uint32_t *a)
{
	memset((void*)(a->data), 0, (a->len)*sizeof(uint32_t));
	a->neg = 0;
}

void b_assign(b_uint32_t *a, uint32_t val)
{
	memset((void*)(a->data), 0, (a->len)*sizeof(uint32_t));
	a->data[a->len-1] = val;
	a->neg = 0;		
}

void b_ctx_init(b_ctx_t* ctx, int len)
{
	ctx->len    = len;
	ctx->depth1 = 0;
	ctx->depth2 = 0;
	ctx->depth4 = 0;

	for (int i = 0; i < B_CTX_SIZE; ++i)
	{
		ctx->ctx1[i].data = malloc(len*sizeof(uint32_t));
		ctx->ctx1[i].len  = len;
		ctx->ctx1[i].neg  = 0;
	}

	for (int i = 0; i < B_CTX_SIZE; ++i)
	{
		ctx->ctx2[i].data = malloc(2*len*sizeof(uint32_t));
		ctx->ctx2[i].len  = 2*len;
		ctx->ctx2[i].neg  = 0;
	}

	for (int i = 0; i < B_CTX_SIZE; ++i)
	{
		ctx->ctx4[i].data = malloc(4*len*sizeof(uint32_t));
		ctx->ctx4[i].len  = 4*len;
		ctx->ctx4[i].neg  = 0;
	}

	return;
}

void b_ctx_save(b_ctx_t* ctx, b_ctx_bkp_t* bkp)
{
	bkp->depth1 = ctx->depth1;
	bkp->depth2 = ctx->depth2;
	bkp->depth4 = ctx->depth4;
}

void b_ctx_restore(b_ctx_t* ctx, b_ctx_bkp_t* bkp)
{
	ctx->depth1 = bkp->depth1;
	ctx->depth2 = bkp->depth2;
	ctx->depth4 = bkp->depth4;
}


b_uint32_t* b_ctx_alloc(b_ctx_t* ctx, int len)
{
	if (len == ctx->len)
	{
		return &ctx->ctx1[ctx->depth1++];
	}
	else if (len>>1 == ctx->len)
	{
		return &ctx->ctx2[ctx->depth2++];
	}
	else
	{
		return &ctx->ctx4[ctx->depth4++];
	}
}

void b_ctx_fini(b_ctx_t* ctx)
{
	for (int i = 0; i < B_CTX_SIZE; ++i)
	{
		free(ctx->ctx1[i].data); 
		free(ctx->ctx2[i].data); 
		free(ctx->ctx4[i].data); 
	}

	return;
}

b_uint32_t* b_create(int len)
{
	b_uint32_t* a = malloc(sizeof(b_uint32_t));
	a->data = calloc(len*sizeof(uint32_t), 1);
	a->len  = len;   
	a->top  = 0;
	a->topbit = 0;
	a->neg  = 0;

	return a;
}

void b_destroy(b_uint32_t* a)
{
	free(a->data);
	a->data = NULL;
	free(a);
	a = NULL;
}

void b_toggle(b_uint32_t* a)
{
	a->neg = !a->neg;
}

void b_swap(b_uint32_t** a, b_uint32_t** b)
{
	b_uint32_t* t;

	t = *a;
	*a = *b;
	*b = t;

	return;
}

/* a b c =>  b c a */
void b_swap3(b_uint32_t** a, b_uint32_t** b, b_uint32_t** c)
{
	b_uint32_t* t;

	t = *a;
	*a = *b;
	*b = *c;
	*c = t;

	return;
}


void dump(char* string, b_uint32_t *a)
{
	printf("%s: ", string);

	if (a->neg)
	{
		printf("neg ");
	}
	for (int i = 0; i < a->len; ++i)
	{
		printf("0x%8x,", a->data[i]);
		/* code */
	}
	printf("\n");
}

/** get the number of valid bit(start with non-zero bit)  
*/
int b_valid_bit(uint32_t a, int* topbit)
{
	int i;

	for (i = 0; i < 32; ++i)
	{
		if (a & (0x80000000 >> i))
		{
			break;
		}
	}

	*topbit = i;
	return (32-i);
}

/* 
   make a->top valid 
   return: the most significant byte of @a
*/
int b_valid_top(b_uint32_t* a)
{
	int len_a = a->len;
	int i;

	for (i = 0; i < len_a; ++i)
	{
		if (a->data[i])
		{
			break;
		}
	}	

	a->top = i;

	return i;
}


/* make a->topbit valid */
/* generally, b_top_valid need to be called */
int  b_valid_topbit(b_uint32_t* a)
{
	int i;
	uint32_t topword = a->data[a->top];
	for (i = 0; i < 32; ++i)
	{
		if (topword & (0x80000000 >> i))
		{
			break;
		}
	}

	a->topbit = i;

	return i;
}

/* a = b*/
void b_mov(b_uint32_t* a, b_uint32_t* b)
{
	if (a == b)
	{
		return;
	}

	int len_a = a->len;
	int len_b = b->len;

	b_zero(a);

	if (len_a <= len_b)
	{
		memcpy(a->data, &b->data[len_b - len_a], len_a*sizeof(uint32_t));
	}
	else
	{
		memcpy(&a->data[len_a - len_b], b->data, len_b*sizeof(uint32_t));
	}

	a->neg = b->neg;

	return;
}


/* a = a + b << l*sizeof(uint32_t) */
void b_add2(b_uint32_t *a, uint32_t b, int l)
{
	int len_a = a->len;
	uint64_t tmp;

	if (l >= len_a)
	{
		return;
	}

	for (int i = len_a - 1 - l; i >= 0; i--)
	{
		tmp = (uint64_t)a->data[i] + (uint64_t)b;

		a->data[i] = tmp & 0xffffffff;

		if (tmp >> 32)
		{
			b = 1;
			continue;
		}
		else
		{
			break;
		}
	}
}

/* c = a + b */
/* return true if overflow */
int b_add(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c)
{
	uint64_t tmp;
	int len_a = a->len;
	int len_b = b->len;
	int len_c = c->len;
	uint64_t carry = 0;

	while(len_a && len_b && len_c)
	{
		tmp = (uint64_t)a->data[len_a-1] + (uint64_t)b->data[len_b-1] + carry;

		c->data[len_c - 1] = (uint32_t)(tmp & 0xffffffff);

		carry = tmp >> 32;

		len_a--;
		len_b--;
		len_c--;
	}

	if (len_c == 0)
	{
		return !!(carry);
	}

	if (len_a)
	{
		while(len_a && len_c)
		{
			tmp = (uint64_t)a->data[len_a-1] + carry;

			c->data[len_c - 1] = (uint32_t)(tmp & 0xffffffff);

			carry = tmp >> 32;

			len_a--;
			len_c--;
		}
	}
	else
	{
		while(len_b && len_c)
		{
			tmp = (uint64_t)b->data[len_b-1] + carry;

			c->data[len_c - 1] = (uint32_t)(tmp & 0xffffffff);

			carry = tmp >> 32;

			len_b--;
			len_c--;
		}
	}

	return !!(carry);
} 


/* a = a - b << l*sizeof(uint32_t) */
void b_sub2(b_uint32_t *a, uint32_t b, int l)
{
	int align = a->len - 1 - l;
	int top;
	int va;
	uint32_t borrow = 0;

	top = b_valid_top(a);
	va = a->len - top;

	do{
		if (borrow)
		{
			if (a->data[align])
			{
				a->data[align]--;
				borrow = 0;
			}
			else
			{
				a->data[align] = 0xffffffff;
			}
		}

		if (a->data[align] >= b)
		{
			a->data[align] -= b; 
			b = 0;
		}
		else
		{
			a->data[align] = 0x100000000 - b + a->data[align];
			borrow = 1;
			b = 0;
		}

		align--;

	}while(borrow);

	return;

}

/* c = a - b 
   a must be greater than b 
*/
void b_sub(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c)
{
	int len_a = a->len;
	int len_b = b->len;
	int len_c = c->len;
	int borrow = 0;

	while(len_a && len_c)
	{
		uint32_t sa = a->data[len_a - 1];
		
		uint32_t sb = len_b > 0 ? b->data[len_b - 1] : 0;

		if (borrow)
		{
			if (sa > 0)
			{
				sa--;
				borrow = 0;
			}
			else
			{
				sa = 0xffffffff;
			}
		}

		if (sa >= sb)
		{
			c->data[len_c - 1] = sa - sb;
		}
		else
		{
			c->data[len_c - 1] = 0xffffffff - sb + sa + 1;
			borrow = 1;
		}

		len_a--;
		len_b--;
		len_c--;
	}

	return;
}


#define COMBA_INIT                                  \
{                                                   \
    uint64_t r;                                      \
 
#define COMBA_MULADDC                               \
                                                    \
    r = (uint64_t)(*px--) * (*py++) + c0;            \
    c0 = (uint32_t)r;                               \
    r = (uint64_t)c1 + (r >> 32);                   \
    c1 = (uint32_t)r;                               \
    c2 += (uint32_t)(r >> 32);                     \
 
#define COMBA_STOP                                  \
}

/* z = x * y */
/* z->len must greater than x->len + y->len */
void b_mul(b_uint32_t *x, b_uint32_t *y, b_uint32_t *z)
{
	uint32_t c0,c1,c2;
	uint32_t* px,*py,*pz;

	int nc, i,j,k,tx,ty;
	int len_x, len_y, len_z;

	len_z = z->len;
	len_x = x->len;
	len_y = y->len;

	b_zero(z);

	c0 = 0;
	c1 = 0;
	c2 = 0;

	pz = &z->data[len_z-1];

	for (int i = len_z-1; i >= 0; i--)
	{
		ty = (i-len_x > 0)?(i-len_x):0;
		tx = i-ty-1;

		k = BN_MIN(len_y-ty, tx+1);

	//	printf("%d,\n", k);

		px = x->data + tx;
		py = y->data + ty;

		c0 = c1;
		c1 = c2;
		c2 = 0;

		j = k;
		 //Comba 32
        for(; j >= 32; j -= 32)
        {
            COMBA_INIT
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
 
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
 
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
 
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_STOP
        }
		 //Comba 16
        for(; j >= 16; j -= 16)
        {
            COMBA_INIT
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
 
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_STOP
        }
        //Comba 8
        for(; j >= 8; j -= 8)
        {
            COMBA_INIT
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_STOP
        }
        //Comba 4
        for(; j >= 4; j -= 4)
        {
            COMBA_INIT
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_MULADDC    COMBA_MULADDC
            COMBA_STOP
        }
        //Comba 1
        for(; j > 0; j--)
        {
            COMBA_INIT
            COMBA_MULADDC
            COMBA_STOP
        }
 
 		*pz-- = c0;
	}

	z->neg = x->neg ^ y->neg;
	return;
}

/** b_cmp -- compare a with b
    if a > b  return 1
       a = b  return 0
       a < b  return -1
    caution: compare in abstract!!!   
*/
int b_cmp(b_uint32_t* a, b_uint32_t* b)
{
	int len_a = a->len;
	int len_b = b->len;
	int va, vb;
	int top_a, top_b;

	top_a = b_valid_top(a);
	top_b = b_valid_top(b);

	va = a->len - a->top;
	vb = b->len - b->top;

	if (va > vb)
	{
		return 1;
	}
	else if (va < vb)
	{
		return -1;
	}

	for (int i = 0; i < va; ++i)
	{
		if (a->data[top_a + i] > b->data[top_b + i])
		{
			return 1;
		}
		else if (a->data[top_a + i] < b->data[top_b + i])
		{
			return -1;
		}
	}

	return 0;
}

int b_cmp2(b_uint32_t* a, uint32_t b)
{
	int top_a;
	int va;

	top_a = b_valid_top(a);
	va = a->len - a->top;

	if (b == 0)
	{
		return va;	
	}

	if (va > 1)
	{
		return 1;
	}
	else if (va == 0)
	{
		return -1;
	}
	
	/* va = 1 */
	if (a->data[a->len-1] > b)
	{
		return 1;
	}
	else if (a->data[a->len-1] == b)
	{
		return 0;
	}
	else
	{
		return -1;
	}

}

/* c = a + b (consider negtive) */
void b_add_ex(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c)
{
	if (a->neg == b->neg)
	{
		b_add(a, b, c);
		c->neg = a->neg;
	}
	else
	{
		if (b_cmp(a, b) > 0)
		{
			b_sub(a, b, c);
			c->neg = a->neg;
		}
		else
		{
			b_sub(b, a, c);
			c->neg = b->neg;
		}
	} 

	return;
}

/* c = a - b (consider negtive */
void b_sub_ex(b_uint32_t *a, b_uint32_t *b, b_uint32_t *c)
{
	if (a->neg == b->neg)
	{
		if (b_cmp(a, b) < 0)
		{
			b_sub(b, a, c);
			c->neg = !a->neg;
		}
		else
		{
			b_sub(a, b, c);
			c->neg = a->neg;
		}
	}
	else
	{
		b_add(a, b, c);
		c->neg = a->neg;
	}

	return;
}

/** c = a << n*32 bit
*/
void b_leftshift(b_uint32_t* a, int n, b_uint32_t* c)
{
	int len_c = c->len;

	/* c = a */
	b_mov(c, a);

	for (int i = 0; i < len_c-n; ++i)
	{
		c->data[i] = c->data[i + n];
	}

	memset(&c->data[len_c-n], 0, n*sizeof(uint32_t));

	return;
}

int b_calcshiftbit(uint32_t a, uint32_t b)
{
	int i = 0;

	if (a == b)
	{
		return 0;
	}

	if (a > b)
	{
		do
		{
			a = a >> 1;
			i++;
		}while(a > b);

		return -(i-1);
	}
	else /* a < b */
	{
		if (a == 0)
		{
			return 32;
		}

		do
		{
			b = b >> 1;
			i++;
		}while(a <= b);

		return i;
	}

	return 0;
}

/* c = a>>b bit
*/
void b_rightshiftbit(b_uint32_t* a, int b, b_uint32_t* c)
{
	b_mov(c, a);

	if (b <= 0 || b >= 32)
	{
		return;
	}

	static const uint32_t mask[32] = {0x00000000,
									  0x00000001,0x00000003,0x00000007,0x0000000f,0x0000001f,0x0000003f,0x0000007f,0x000000ff,
									  0x000001ff,0x000003ff,0x000007ff,0x00000fff,0x00001fff,0x00003fff,0x00007fff,0x0000ffff,
									  0x0001ffff,0x0003ffff,0x0007ffff,0x000fffff,0x001fffff,0x003fffff,0x007fffff,0x00ffffff,
									  0x01ffffff,0x03ffffff,0x07ffffff,0x0fffffff,0x1fffffff,0x3fffffff,0x7fffffff};

	for (int i = c->len-1; i > 0; i--)
	{
		c->data[i] = (c->data[i] >> b) | ((c->data[i-1] & mask[b])<< (32-b));
	}

	c->data[0] = c->data[0] >> b;

	return;
}

/* c = a << b bit
*/
void b_leftshiftbit(b_uint32_t* a, int b, b_uint32_t* c)
{
	b_mov(c, a);

	if (b <= 0 || b >= 32)
	{
		return;
	}	

	static const uint32_t mask[32] = {0x00000000,
									  0x80000000,0xc0000000,0xe0000000,0xf0000000,0xf8000000,0xfc000000,0xfe000000,0xff000000,
	                                  0xff800000,0xffc00000,0xffe00000,0xfff00000,0xfff80000,0xfffc0000,0xfffe0000,0xffff0000,
	                                  0xffff8000,0xffffc000,0xffffe000,0xfffff000,0xfffff800,0xfffffc00,0xfffffe00,0xffffff00,
	                                  0xffffff80,0xffffffc0,0xffffffe0,0xfffffff0,0xfffffff8,0xfffffffc,0xfffffffe};

	for (int i = 0; i < (c->len-1); i++)
	{
		c->data[i] = (c->data[i] << b) | ((c->data[i+1] & mask[b]) >> (32-b));
	}

	c->data[c->len-1] = c->data[c->len-1] << b;

	return;
}


/* c = a mod n   */
void b_mod(b_uint32_t* a, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx)
{
	int vres; /* valid of c */
	int vn; /* valid of n */
	int s;
	b_uint32_t* tmp;
	b_uint32_t* res;

	if (b_cmp(a, n) < 0)
	{
		b_mov(c, a);
		return;
	}

	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	tmp = b_ctx_alloc(ctx, a->len);	
	b_zero(tmp);

	res = b_ctx_alloc(ctx, a->len);
	b_mov(res, a); 

	b_valid_top(res);
	b_valid_top(n);

	vres = res->len - res->top;
	vn = n->len - n->top;

	while(vres > vn)
	{
		b_leftshift(n, vres - vn, tmp);

		//s = c_topbit + 1 - n_topbit;

		s = b_calcshiftbit(res->data[res->top], n->data[n->top]);

		if (s > 0)
		{
			if (s == 32)
			{
				b_leftshift(n, vres - vn - 1,tmp);
			}
			else
			{
				b_rightshiftbit(tmp, s, tmp);
			}
		}
		else if (s < 0)
		{
			b_leftshiftbit(tmp, -s, tmp);
		}

		/* c = c - tmp */
		b_sub(res, tmp, res);

		/* update c */
		b_valid_top(res);
		vres = res->len - res->top;
		//c_topbit = b_valid_topbit(c);
	}

	if (vres == vn)
	{
		while(b_cmp(res, n) >= 0)
		{
			s = b_calcshiftbit(res->data[res->top], n->data[n->top]);

			b_mov(tmp, n);
			if (s > 0)
			{
				b_rightshiftbit(tmp, s, tmp);
			}
			else if (s < 0)
			{
				b_leftshiftbit(tmp, -s, tmp);
			}

			b_sub(res, tmp, res);
		}
	}

	b_mov(c, res);


	b_ctx_restore(ctx, &bkp);

	return;
}


void b_mod_ex(b_uint32_t* a, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx)
{
	if (0 == a->neg)
	{
		/* a is positive */
		b_mod_ex(a, n, c, ctx);
		return;
	}

	b_uint32_t* _a;	
	b_ctx_bkp_t bkp;
	volatile int neg = 1;
	b_ctx_save(ctx, &bkp);

	_a = b_ctx_alloc(ctx, n->len);
	b_mov(_a, a);

	/* inc _a until _a is positive */
	do {
		b_add_ex(_a, n, _a);
		neg = _a->neg;
	}while(neg);

	b_mod_ex(_a, n, c, ctx);

	b_ctx_restore(ctx, &bkp);

	return;
}

/* c = a + b mod n */
void b_addmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx)
{
	b_uint32_t* _a;	
	b_uint32_t* _b;
	b_uint32_t* tmp;
	int overflow;
	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	_a = b_ctx_alloc(ctx, n->len);
	_b = b_ctx_alloc(ctx, n->len);
	tmp = b_ctx_alloc(ctx, n->len);

	b_mod(a, n, _a, ctx);
	b_mod(b, n, _b, ctx);

	overflow = b_add(_a, _b, tmp);
	if (overflow)
	{
		b_sub(n, _a, tmp);
		b_sub(_b, tmp, c);
	}
	else
	{
		b_mod(tmp, n, c, ctx);
	}

	c->neg = 0;

	b_ctx_restore(ctx, &bkp);

	return;
}

/* c = a - b mod n */
/* note: a,b > 0*/
void b_submod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx)
{
	b_uint32_t* _a;	
	b_uint32_t* _b;
	b_uint32_t* _c;
	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	if (c == a)
	{
		/* calculate in place */
		_c = b_ctx_alloc(ctx, n->len);		
	}
	else
	{
		_c = c;
	}
	b_zero(_c);

	_a = b_ctx_alloc(ctx, n->len);
	_b = b_ctx_alloc(ctx, n->len);

	b_mod(a, n, _a, ctx);
	b_mod(b, n, _b, ctx);

	/* now  0 < _a,_b < n */
	b_sub_ex(_a, _b, _c);
	if (_c->neg)
	{
		b_add_ex(_c, n, _c);
	}

	if (c == a)
	{
		b_mov(c, _c);
	}

	b_ctx_restore(ctx, &bkp);

	return;
}

/* c = a * b mod n  */
void b_mulmod(b_uint32_t *a, b_uint32_t *b, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx)
{
	b_uint32_t* pd;	
	b_uint32_t* _a;	
	b_uint32_t* _b;	
	b_uint32_t* _c;	
	b_ctx_bkp_t bkp;

	b_ctx_save(ctx, &bkp);
	_a = b_ctx_alloc(ctx, n->len);
	_b = b_ctx_alloc(ctx, n->len);
	if (c == a)
	{
		/* calculate in place */
		_c = b_ctx_alloc(ctx, n->len);
	}
	else
	{
		_c = c;
	}
	b_zero(_c);

	b_mod(a, n, _a, ctx);
	b_mod(b, n, _b, ctx);

	pd = b_ctx_alloc(ctx, n->len<<1);	
	b_zero(pd);

	b_mul(_a, _b, pd);
	
	b_mod(pd, n, _c, ctx); 
	if (c == a)
	{
		b_mov(c, _c);
	}

	b_ctx_restore(ctx, &bkp);

	return;
}

/* c = a^x mod n */
void b_expmod(b_uint32_t *a, b_uint32_t* x, b_uint32_t *n, b_uint32_t *c, b_ctx_t* ctx)
{
	b_uint32_t* res;
	b_uint32_t* _a;
	int top;
	int topbit;

	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	_a  = b_ctx_alloc(ctx, n->len);
	b_mod(a, n, _a, ctx);

	res = b_ctx_alloc(ctx, n->len);	
	
	/* Initialization */
	b_mov(res, _a);

	top = b_valid_top(x);
	topbit = b_valid_topbit(x);

	for (int i= top*32 + topbit+1; i<(x->len)*32; ++i)
	{
		b_mulmod(res, res, n, res, ctx); 

		if (x->data[i/32] & (0x80000000 >> (i%32)))
		{
			b_mulmod(res, _a, n, res, ctx);
		}
	}

	b_mov(c, res);

	b_ctx_restore(ctx, &bkp);

	return;
}


/* de / di  = q ... r */
void b_div(b_uint32_t* de, b_uint32_t* di, b_uint32_t* q, b_uint32_t* r, b_ctx_t* ctx)
{
	b_uint32_t* tmp;
	int vr;
	int vdi;
	int top_r;
	int top_di;
	uint32_t mdi;

	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);
	tmp = b_ctx_alloc(ctx, de->len);	
	b_zero(tmp);
	
	b_zero(q);

	/* r = a */
	b_mov(r, de);

	if (b_cmp(de, di) < 0)
	{
		return;
	}

	top_r  = b_valid_top(r);
	top_di = b_valid_top(di);

	vr  = r->len - top_r;
	vdi = di->len - top_di;

	mdi = di->data[top_di];

	while(vr > vdi)
	{
		int s = 0;

		s = b_calcshiftbit(r->data[r->top], mdi);
		if (s == 0)
		{
			b_leftshift(di, vr - vdi, tmp);
			b_add2(q, 0x00000001, vr - vdi);
		}
		else if (s == 32)
		{
			b_leftshift(di, vr - vdi - 1, tmp);
			b_add2(q, 0x00000001, vr - vdi - 1);
		}
		else if (s > 0)
		{
			b_leftshift(di, vr - vdi, tmp);
			b_rightshiftbit(tmp, s, tmp);
			b_add2(q, 0x80000000 >> (s-1), vr - vdi - 1);
		}
		else /* s < 0 */
		{
			b_leftshift(di, vr - vdi, tmp);
			b_leftshiftbit(tmp, -s, tmp);
			b_add2(q, 0x00000001 << -s, vr - vdi);
		}

		b_sub(r, tmp, r);

		vr = r->len - b_valid_top(r);
	}

	if (vr == vdi)
	{
		while(b_cmp(r, di) >= 0)
		{
			int s = 0;

			s = b_calcshiftbit(r->data[r->top], mdi);
			b_mov(tmp, di);
			if (s == 0)
			{
				b_add2(q, 0x00000001, vr - vdi);
			}
			else if (s < 0)
			{
				b_leftshiftbit(tmp, -s, tmp);
				b_add2(q, 0x00000001 << -s, 0);
			}			
			b_sub(r, tmp, r);
		}
	}

	b_ctx_restore(ctx, &bkp);

	return;
}

/*****************************************************/
int is_prime(b_uint32_t* p, int security, b_ctx_t* ctx)
{
	#define MR_SECURITY_MAX 9
	uint32_t mr_base[MR_SECURITY_MAX] = {2, 3, 5, 7, 11, 13, 17, 19, 23};
	int isprime = 0;
	b_uint32_t* pm1;
	b_uint32_t* r;
	b_uint32_t* z;
	b_uint32_t* base;
	b_ctx_bkp_t bkp;
	
	b_ctx_save(ctx, &bkp);

	/* Initialize pm1 = p - 1 */
	pm1 = b_ctx_alloc(ctx, p->len);	
	b_mov(pm1, p);
	b_sub2(pm1, 0x00000001, 0);

	/* r = pm1 */
	r = b_ctx_alloc(ctx, p->len);	
	b_mov(r, pm1);

	z = b_ctx_alloc(ctx, p->len);
	b_zero(z);

	base = b_ctx_alloc(ctx, p->len);
	b_zero(base);


	int u = 0;
	do{
		b_rightshiftbit(r, 1, r);
		u++;
	}while(!(r->data[r->len-1] & 0x00000001));

	for (int i = 0; i < security; ++i)
	{
		int pass = 0;

		base->data[base->len-1] = mr_base[i];
		/* z = a^r mod p */
		b_expmod(base, r, p, z, ctx); 
		
		if (b_cmp2(z, 0x00000001) && b_cmp(z, pm1))
		{
			for (int j = 1; j < u; ++j)
			{
				/* z = z^2 mod p */
				b_mulmod(z, z, p, z, ctx);  
				if (!b_cmp2(z, 0x00000001))
				{
					isprime = 0;
					goto done;
				}
				if (!b_cmp(z, pm1))
				{
					pass = 1;
					break;
				}
			}

			if (!pass)
			{
				if (b_cmp(z, pm1))
				{
					isprime = 0;
					goto done;
				}				
			}
		}
	}

	isprime = 1;

done:

	b_ctx_restore(ctx, &bkp);

	return isprime;
}


void b_random(b_uint32_t* a)
{
	static unsigned long seed = 0;
	int len_a = a->len;

	if (seed == 0)
	{
		time_t t;
		t = time(NULL);
		seed = (unsigned long)t;
		srand(seed);
	}

	b_zero(a);

	for (int i = 0; i < len_a; ++i)
	{
		a->data[i] = rand() & 0xff;
		a->data[i] |= (rand() & 0xff) << 8;
		a->data[i] |= (rand() & 0xff) << 16;
		a->data[i] |= (rand() & 0xff) << 24;
	}

	a->data[0] |= 0x80000000;
	//seed = a->data[0];

	return;
}

/* make a num odd */
void b_odd(b_uint32_t* a)
{
	if (!(a->data[a->len-1] & 0x01))
	{
		b_add2(a, 1, 0); /* a = a + 1 */
	}

	return;
}

/*
  generate a random prime 
*/
void prime_random(b_uint32_t* p, b_ctx_t* ctx)
{
	b_uint32_t* ten;
	b_uint32_t* rten;
	b_ctx_bkp_t bkp;
	
	b_ctx_save(ctx, &bkp);
	ten = b_ctx_alloc(ctx, p->len);	
	b_assign(ten, 0x0000000A);

	rten = b_ctx_alloc(ctx, p->len);	
	b_zero(rten);

	b_random(p);
	p->data[0] |= 0x80000000;

	b_odd(p);

	/* calc p%10 */
	b_mod(p, ten, rten, ctx);
	
	int try = 1;
	try = rten->data[rten->len-1]>>1; //  try = 0\1\2\3\4
	if (try == 2)
	{
		try++;
		b_add2(p , 0x00000002, 0);
	}

	while (!is_prime(p, 3, ctx))
	{
		if (try%5 == 1)
		{
			try += 2;
			b_add2(p , 0x00000004, 0);
		}
		else{
			try++;
			b_add2(p , 0x00000002, 0);
		}
	}
	
	b_ctx_restore(ctx, &bkp);

	return;
}

void euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_ctx_t* ctx)
{	
	if (b_cmp(r0, r1) < 0)
	{
		euclidean_algorithm(r1, r0, gcd, ctx);
		return;
	}

	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	b_uint32_t* r[3];
	r[0] = b_ctx_alloc(ctx, r0->len); 
	r[1] = b_ctx_alloc(ctx, r0->len); 
	r[2] = b_ctx_alloc(ctx, r0->len); 

	b_mov(r[0], r0);
	b_mov(r[1], r1);
	b_zero(r[2]);

	do{
		b_mod(r[0], r[1], r[2], ctx); 
		b_swap3(&r[0], &r[1], &r[2]);
	}while(b_cmp2(r[1], 0));

	b_mov(gcd, r[0]);

	b_ctx_restore(ctx, &bkp);

	return;
}

/*
	positive integers r0 and r1 with r0 > r1
    gcd(r0, r1) = s*r0 + t*r1  

    r0, r1 given, we calculate gcd

    if gcd == 1, then t is the inverse of r1 mod r0
*/
void ex_euclidean_algorithm(b_uint32_t* r0, b_uint32_t* r1, b_uint32_t* gcd, b_uint32_t* t, b_ctx_t* ctx)
{
	int i = 0;
	int len_r0 = r0->len;
	b_uint32_t* r[3];
	b_uint32_t* cor1[3];
	b_uint32_t* q;
	b_uint32_t* qc;
	
	if (r0->neg || r1->neg || (b_cmp(r0, r1)<=0))
	{
		return;
	}

	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	r[0] = b_ctx_alloc(ctx, len_r0);
	r[1] = b_ctx_alloc(ctx, len_r0);
	r[2] = b_ctx_alloc(ctx, len_r0);
	cor1[0] = b_ctx_alloc(ctx, len_r0);
	cor1[1] = b_ctx_alloc(ctx, len_r0);
	cor1[2] = b_ctx_alloc(ctx, len_r0);
	q  = b_ctx_alloc(ctx, len_r0);
	qc = b_ctx_alloc(ctx, len_r0<<1);

	b_mov(r[0], r0);
	b_mov(r[1], r1);

	b_zero(gcd);
	b_zero(cor1[0]);   
	b_assign(cor1[1], 0x00000001);   
	b_zero(cor1[2]); 

	do {
		b_div(r[0], r[1], q, r[2], ctx); 

		/* qc = q*cor1[1] */
		b_mul(q, cor1[1], qc);

		/* qc = -qc */
		b_toggle(qc);
		/* cor1[2] = cor1[0] - q*cor1[1] */
		b_add_ex(cor1[0], qc, cor1[2]);

		b_swap3(&cor1[0], &cor1[1], &cor1[2]);	
		b_swap3(&r[0], &r[1], &r[2]);	
	}while(b_cmp2(r[1],0));

	b_mov(gcd, r[0]);

	if (cor1[0]->neg)
	{
		b_add_ex(cor1[0], r0, t);
	}
	else
	{
		b_mov(t, cor1[0]);
	}
	

	b_ctx_restore(ctx, &bkp);

	return;
}

/* 
   return 0: t = a^(-1) mod n 
		 -1: t is not exist
 */
int b_inverse(b_uint32_t* a, b_uint32_t* n, b_uint32_t* t, b_ctx_t* ctx)
{
	int rc = -1;
	b_uint32_t* gcd;
	b_uint32_t* _a;    
	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);

	b_zero(t);

	_a  = b_ctx_alloc(ctx, n->len);
	b_mov(_a, a);

	while (_a->neg)
	{
		b_add_ex(_a, n, _a);
	}

	gcd = b_ctx_alloc(ctx, n->len);

	ex_euclidean_algorithm(n, _a, gcd, t, ctx);

	if (0 == b_cmp2(gcd, 1))
	{
		rc = 0;
	}

	b_ctx_restore(ctx, &bkp);

	return rc;
}

/*
 *  c = a/b mod n
    return  0: success
    return -1: b^(-1) is not exist 
 */
int b_divmod(b_uint32_t* a, b_uint32_t* b, b_uint32_t* n, b_uint32_t* c, b_ctx_t* ctx)
{
	int rc = -1;
	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);
	b_uint32_t* ib; /* inverse of b */

	b_zero(c);

	ib = b_ctx_alloc(ctx, n->len);

	rc = b_inverse(b, n, ib, ctx);
	if (0 == rc)
	{
		b_mulmod(a, ib, n, c, ctx);		
	}

	b_ctx_restore(ctx, &bkp);
	return rc;
}


int is_coprime(b_uint32_t* a, b_uint32_t* b, b_ctx_t* ctx)
{
	int prime = 0;
	b_uint32_t* gcd;
	
	b_ctx_bkp_t bkp;
	b_ctx_save(ctx, &bkp);
	gcd = b_ctx_alloc(ctx, a->len);

	euclidean_algorithm(a, b, gcd, ctx);

	if (!b_cmp2(gcd, 0x1))
	{
		prime = 1;
	}	

	b_ctx_restore(ctx, &bkp);

	return prime;
}