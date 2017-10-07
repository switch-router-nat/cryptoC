/*
 * File       : rolate_shift.c *
 * Change Logs:
 * Date           Author       Notes
 * 2017-10-05     QshLyc       first version
 */
#include <stdint.h>
#include "rolate_shift.h"


/*
    rolate shift @word @l bit 
*/
uint32_t Rotl32(uint32_t word, uint8_t l)
{
	uint32_t w;
	
	w = (word << l) | (word >> (32 - l));

	return w;
}




