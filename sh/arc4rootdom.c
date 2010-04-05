/*-
 * Copyright (c) 2009
 *	Thorsten Glaser <tg@mirbsd.org>
 *
 * Provided that these terms and disclaimer and all copyright notices
 * are retained or reproduced in an accompanying document, permission
 * is granted to deal in this work without restriction, including un-
 * limited rights to use, publicly perform, distribute, sell, modify,
 * merge, give away, or sublicence.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind, to
 * the utmost extent permitted by applicable law, neither express nor
 * implied; without malicious intent or gross negligence. In no event
 * may a licensor, author or contributor be held liable for indirect,
 * direct, other damage, loss, or other issues arising in any way out
 * of dealing in the work, even if advised of the possibility of such
 * damage or existence of a defect, except proven that it results out
 * of said person's immediate fault when using the work as intended.
 *-
 * arc4random_pushb for Android (and mksh on it)
 *
 * This basically assumes we're root, have /dev/urandom and can write
 * to it, with OpenBSD/Linux semantics. When we are not root, the en-
 * tropy is *LOST*, so this is not generic!
 */

static const char __rcsid[] =
    "$MirOS: contrib/hosted/tg/arc4rootdom.c,v 1.1 2009/11/29 17:56:51 tg Exp $";

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint32_t arc4random_pushb(const void *, size_t);

#ifndef MIN
#define	MIN(a,b)	(((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define	MAX(a,b)	(((a)>(b))?(a):(b))
#endif

uint32_t
arc4random_pushb(const void *buf, size_t len)
{
	size_t j;
	int fd;
	union {
		uint8_t buf[256];
		struct {
			struct timeval tv;
			const void *sp, *dp;
			size_t sz;
			uint32_t vu;
		} s;
	} uu;
	struct {
		uint32_t h;
		uint16_t u;
		uint8_t k[8];
	} av;

	memcpy(uu.buf, __rcsid, MIN(sizeof(uu.buf), sizeof(__rcsid)));

	{
		register uint32_t h;
		register size_t n = 0;
		register uint8_t c;

		av.u = arc4random() & 0xFFFF;
		uu.s.sp = &uu;
		uu.s.dp = buf;
		uu.s.sz = len;
		uu.s.vu = arc4random();
		gettimeofday(&uu.s.tv, NULL);

		h = arc4random() & 0xFFFFFF00;
		j = 0;
		while (j < sizeof(uu.s)) {
			h += ((uint8_t *)&uu)[j++];
			h += h << 10;
			h ^= h >> 6;
		}
		j = MAX(len, sizeof(uu.s));

		while (n < j) {
			c = ((const uint8_t *)buf)[n % len];
			uu.buf[n % sizeof(uu.buf)] ^= c;
			h += c;
			h += h << 10;
			h ^= h >> 6;
			++n;
		}

		len = MIN(sizeof(uu), j);
		h += h << 3;
		h ^= h >> 11;
		h += h << 15;
		av.h = h;
	}

	if ((fd = open("/dev/urandom", O_RDWR)) != -1) {
		av.u += write(fd, &uu, len);
		av.u += read(fd, av.k, sizeof(av.k));
		av.u += close(fd);
	}
	av.u += fd;

	arc4random_addrandom((void *)&av, sizeof(av));
	return (arc4random());
}
