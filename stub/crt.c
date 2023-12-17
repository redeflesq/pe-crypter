#include "crt.h"

void* memmove(void* dest, const void* src, unsigned int n)
{
	unsigned char* from = (unsigned char*)src;
	unsigned char* to = (unsigned char*)dest;

	if (from == to || n == 0)
		return dest;
	if (to > from && to - from < (int)n) {
		/* to overlaps with from */
		/*  <from......>         */
		/*         <to........>  */
		/* copy in reverse, to avoid overwriting from */
		int i;
		for (i = n - 1; i >= 0; i--)
			to[i] = from[i];
		return dest;
	}
	if (from > to && from - to < (int)n) {
		/* to overlaps with from */
		/*        <from......>   */
		/*  <to........>         */
		/* copy forwards, to avoid overwriting from */
		unsigned int i;
		for (i = 0; i < n; i++)
			to[i] = from[i];
		return dest;
	}
	memcpy(dest, src, n);
	return dest;
}

void* memcpy(void* dest, const void* src, unsigned int n)
{
#ifdef WIN32
	_asm
	{
		mov        edi, [dest]
		mov        esi, [src]
		mov        ecx, [n]
		rep        movsb
	}
#else
	// Typecast src and dest addresses to (char *)  
	char* csrc = (char*)src;
	char* cdest = (char*)dest;

	// Copy contents of src[] to dest[]  
	for (int i = 0; i < n; i++)
		cdest[i] = csrc[i];
#endif
	return dest;
}

// https://stackoverflow.com/questions/18851835/create-my-own-memset-function-in-c
void* memset(void* b, int c, int len)
{
#ifdef WIN32
	_asm
	{
		pushad
		mov        edi, [b]
		mov        ecx, [len]
		mov        eax, [c]
		rep        stosb
		popad
	}
#else
	int i;
	unsigned char* p = b;
	i = 0;
	while (len > 0)
	{
		*p = c;
		p++;
		len--;
	}
#endif
	return(b);
}