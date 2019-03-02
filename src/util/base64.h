/*
 * File       :  base64.h
 *
 * Change Logs:
 * Date           Author       Notes
 * 2017-11-19     187J3X1       first version
 */

#ifndef _CRYPTOC_BASE64_H_
#define _CRYPTOC_BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif

uint32_t cc_base64_encode(const uint8_t* plaintext, uint32_t size, uint8_t* base64);
uint32_t cc_base64_decode(const uint8_t* base64, uint32_t base64size, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
