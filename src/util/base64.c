/*
 * File       :  base64.c
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-21     187J3X1       first version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char* base64enc_tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64dec_tbl[]= 
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    62, // '+'
    0, 0, 0,
    63, // '/'
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
    0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
    0, 0, 0, 0, 0, 0,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
};



uint32_t cc_base64_encode(const char* plaintext, uint32_t size, char* base64)
{
    uint8_t b1,b2,b3;
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t base64size;
    while (i < size) 
    {
        b1 = plaintext[i++];
        b2 = (i < size) ? plaintext[i++] : 0;
        b3 = (i < size) ? plaintext[i++] : 0;

        base64[j++] = base64enc_tbl[(b1 >> 2) & 0x3F];
        base64[j++] = base64enc_tbl[((b1 << 4) | (b2 >> 4)) & 0x3F];
        base64[j++] = base64enc_tbl[((b2 << 2) | (b3 >> 6)) & 0x3F];
        base64[j++] = base64enc_tbl[b3 & 0x3F];
    }

    base64size = j;
    switch (size % 3) 
    {
        case 1:
        base64[--j] = '=';
        case 2:
        base64[--j] = '=';
    }

    return base64size;
}


uint32_t cc_base64_decode(const char* base64, uint32_t base64size, char *plaintext) 
{
    uint32_t i = 0;
    uint32_t j = 0;
    uint8_t n1,n2,n3,n4;
    while (j < base64size)
    {
        n1 = base64dec_tbl[(uint8_t)base64[j++]];
        n2 = base64dec_tbl[(uint8_t)base64[j++]];
        n3 = base64dec_tbl[(uint8_t)base64[j++]];
        n4 = base64dec_tbl[(uint8_t)base64[j++]];

        plaintext[i++] = (n1 << 2) | (n2 >> 4);

        if (base64[j-2] == '=')
        {
            break;
        }

        plaintext[i++] = (n2 << 4) | (n3 >> 2);

        if (base64[j-1] == '=')
        {
            break;
        }

        plaintext[i++] = (n3 << 6) | n4;
    }

    return i;
}
