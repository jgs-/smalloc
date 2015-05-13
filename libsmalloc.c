#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UINTPTR_MAX             0xffffffffffffffffUL
#define SIZE_MAX		UINTPTR_MAX
#define MUL_NO_OVERFLOW		(1UL << (sizeof(size_t) * 4))

void *__syscall(quad_t number, ...);

void *
malloc(size_t size)
{
	void *p;

	/* printf("-- smalloc --\n"); */
	p = __syscall(332, NULL, size);
	return p;
}

void *
realloc(void *p, size_t size)
{
	void *r;

	r = __syscall(332, p, size);
	return r; 
}

void *
calloc(size_t nmemb, size_t size)
{
	void *p;

	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size)
		return NULL;

	size *= nmemb;
	p = __syscall(332, NULL, size);
	memset(p, '\0', size);
	return p;
}

void
free(void *ptr)
{
	if (ptr)
		__syscall(331, (unsigned long)ptr);
}
