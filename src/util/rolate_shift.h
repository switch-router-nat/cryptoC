/*
 * File       : rolate_shift.h *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-05     187J3X1       first version
 */
#ifndef _ROLATE_SHIFT_H_
#define _ROLATE_SHIFT_H_

#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define ROTATE_RIGHT(x,n) ((x >> n) | (x << (32-n)))

uint32_t Rotl32(uint32_t word, uint8_t l);
uint32_t Rotr32(uint32_t word, uint8_t l);
uint64_t Rotl64(uint64_t word, uint8_t l);
uint64_t Rotr64(uint64_t word, uint8_t l);


#endif