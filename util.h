/*
 * Copyright (c) 2018 genua GmbH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <signal.h>
#include <setjmp.h>

#if defined(__PPC__)
#define CACHELINESIZE	32
#elif defined(__i386__) || defined(__amd64__)
#define CACHELINESIZE	64

static int		 _has_rdtscp;
static int		 _has_tsx;
#else
#error "unsupported architecture"
#endif

static sigjmp_buf	_jmpbuf;

static void
sighandler(int signum)
{
	signal(signum, sighandler);
	siglongjmp(_jmpbuf, 1);
}

static inline void
pipeline_flush(void)
{
#if defined(__PPC__)
	asm volatile ("sync; isync");
#elif defined(__i386__) || defined(__amd64__)
	asm volatile ("mfence");
#endif
}

static inline void
cache_flush(volatile void *addr)
{
	unsigned long	a = (unsigned long)addr;
	a &= ~(CACHELINESIZE - 1);
#if defined(__PPC__)
	asm volatile ("dcbf 0,%0" :: "r" (a));
	if (a != (unsigned long)addr) {
		a += CACHELINESIZE;
		asm volatile ("dcbf 0,%0" :: "r" (a));
	}
	asm volatile ("sync");
#elif defined(__i386__) || defined(__amd64__)
	asm volatile ("clflush (%0)" :: "r" ((volatile char *)a) : "memory");
	if (a != (unsigned long)addr) {
		a += CACHELINESIZE;
		asm volatile ("clflush (%0)" :: "r" ((volatile char *)a) : "memory");
	}
#endif
}

static inline uint64_t
read_timer(volatile int *a)
{
	uint64_t ts;

#if defined(__PPC__)
	asm volatile ("1: mftbu %0; mftb %0+1; mftbu %1;"
	    " cmpw 0,%0,%1; bne 1b" : "=r"(ts), "=r"(*a));
#elif defined(__i386__) || defined(__amd64__)
	uint32_t clow, chigh;

	pipeline_flush();
	if (_has_rdtscp) {
		asm volatile (
		    "rdtscp\n"
		    "mov %%edx, %0\n"
		    "mov %%eax, %1\n"
		    : "=g" (chigh), "=g" (clow) :: "edx", "eax", "ecx");
	} else {
		asm volatile (
		    "rdtsc\n"
		    "mov %%edx, %0\n"
		    "mov %%eax, %1\n"
		    : "=g" (chigh), "=g" (clow) :: "edx", "eax");
	}
	ts = ((uint64_t)chigh) << 32 | clow;
	pipeline_flush();
#endif
	return ts;
}


static inline unsigned
timedaccess(volatile char *addr)
{
	uint64_t t0, t1;
	volatile int junk = junk;

	t0 = read_timer(&junk);
	junk |= *addr;
	t1 = read_timer(&junk);

	return (unsigned)(t1 - t0);
}

static inline int
xbegin(void)
{
	int ret = 1;
#if defined(__i386__) || defined(__amd64__)
	if (_has_tsx)
		asm volatile (".byte 0xc7,0xf8 ; .long 0" :
		    "+a" (ret) :: "memory");
	else
#endif
	{
		signal(SIGSEGV, sighandler);
		signal(SIGBUS, sighandler);
		if (sigsetjmp(_jmpbuf, 1) != 0)
			ret = 0;
	}
	return ret;
}

static inline void
xend(void)
{
#if defined(__i386__) || defined(__amd64__)
	if (_has_tsx)
		asm volatile (".byte 0x0f,0x01,0xd5" ::: "memory");
#endif
}

static void
calibrate_clock(int verbose, int *threshold)
{
	volatile char buf[2 * CACHELINESIZE];
	volatile char *bufp;
	volatile int junk = 0;
	int i;
	const int cnt = 1000000;
	uint64_t tcache, tmem;

#if defined(__PPC__)
	/* Nothing to do */
#elif defined(__i386__) || defined(__amd64__)
	unsigned cap;

#if defined(__i386__)
#define PUSH(r)		"pushl	%%e" #r "x\n"
#define POP(r)		"popl	%%e" #r "x\n"
#elif defined(__amd64__)
#define PUSH(r)		"pushq	%%r" #r "x\n"
#define POP(r)		"popq	%%r" #r "x\n"
#endif

	asm volatile (
	    PUSH(a)
	    PUSH(b)
	    PUSH(c)
	    PUSH(d)
	    "mov	$0x80000001,%%eax\n"
	    "mov	$0,%%ecx\n"
	    "cpuid\n"
	    "mov	%%edx,%0\n"
	    POP(d)
	    POP(c)
	    POP(b)
	    POP(a)
	    : "=m" (cap)
	    /*
	     * clang sometimes stores the result using an offset relative to
	     * %esp! That won't work, because we modify %esp with push and pop.
	     * Hence, prevent them compiler from using %esp!
	     */
	    :: "esp" );

#define HAVE_RDTSCP	(1U << 27)
	if (cap & HAVE_RDTSCP) {
		if (verbose)
			printf("CPU has RDTSCP\n");
		_has_rdtscp = 1;
	} else {
		if (verbose)
			printf("WARNING: CPU has no RDTSCP support!\n");
		_has_rdtscp = 0;
	}

	/* On i386 PIC we have to preserve %ebx, too */
	asm volatile (
	    PUSH(a)
	    PUSH(b)
	    PUSH(c)
	    PUSH(d)
	    "mov	$0x7,%%eax\n"
	    "mov	$0,%%ecx\n"
	    "cpuid\n"
	    "mov	%%ebx, %0\n"
	    POP(d)
	    POP(c)
	    POP(b)
	    POP(a)
	    : "=m" (cap)
	    :: "esp" );
#define HAVE_HLE	(1U << 4)
#define HAVE_RTM	(1U << 11)
#define HAVE_TSX	(HAVE_HLE | HAVE_RTM)
	if ((cap & HAVE_TSX) == HAVE_TSX) {
		if (verbose)
			printf("CPU has TSX\n");
		_has_tsx = 1;
	} else {
		if (verbose)
			printf("CPU has no TSX support!\n");
		_has_tsx = 0;
	}
#endif

	bufp = ((volatile void *)(((unsigned long)(buf) + CACHELINESIZE) &
	    ~(CACHELINESIZE - 1)));

	junk |= *bufp;
	for (i = 0, tcache = 0; i < cnt; i++)
		tcache += timedaccess(bufp);
	tcache /= cnt;

	for (i = 0, tmem = 0; i < cnt; i++) {
		cache_flush(bufp);
		pipeline_flush();
		tmem += timedaccess(bufp);
	}
	tmem /= cnt;
	if (threshold != NULL) {
		*threshold = tcache + (tmem - tcache) / 2;
		if (*threshold == (int)tmem)
			(*threshold)--;
	}

	if (verbose) {
		printf("Access time: memory %llu, cache %llu", tmem, tcache);
		if (threshold)
			printf(" -> threshold %d", *threshold);
		printf("\n");
	}

	/* Return suggested threshold for cache access */
	return;
}

