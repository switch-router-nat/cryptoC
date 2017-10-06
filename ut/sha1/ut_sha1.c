#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/base/basetype.h"
#include "../../src/base/object.h"
#include "../../src/hash/sha.h"
#include "../../src/hash/sha1.h"


int main()
{
	cc_uint32_t size[2];
	cc_uint8_t digest[20];
	cc_uint8_t* data;
	cc_uint8_t* data_str = "To be, or not to be- that is the question: whether it's nobler in the mind to suffer the slings and arrows of outrageous fortune, or to take arms against a sea of troubles, and by opposing end them? To die:to sleep;no more; andby a sleep to say we end the heartache and the thousand natural shocks that flesh is heir to. 'tis a consummation devoutly to be wish'd. To die: to sleep; To sleep: perchance to dream: ay, there's the rub: for in that sleep of death what dreams may come when we have shuffled off this mortal coil, must give us pause: there's the respect that makes calamity of so long life;For who would bear the whips and scorns of time, the oppressor's wrong, the proud man's contumely, the pangs of despis'd love, the law's delay, the insolence of office, and the spurns that patient merit of the unworthy takes, when he himself might his quietus make with a bare bodkin? Who would fardels bear, to grunt and sweat under a weary life, but that the dread of something after death, the undiscover'd country, from whose bourn no traveller returns, puzzles the will and makes us rather bear those ills we have than fly to others that we know not of? Thus conscience does make cowards of us all; And thus the native hue of resolution is sicklied o'er with the pale cast of thought, and enterprises of great pith and moment with this regard their currents turn awry, and lose the name of action.";
	cc_uint8_t i;
	
	data = (cc_uint8_t*)malloc(strlen(data_str));
	memcpy(data ,data_str, strlen(data_str));

	void* sha1 = new(Sha1);

	size[0] = 0;
	size[1] = strlen(data_str) << 3;

	SHA_CalculateDigest(sha1, data, size, digest);

	for (i = 0; i < 20; i++)
	{
		printf("0x%x ", digest[i]);
	}

	delete(sha1);

	return 0;	
}

