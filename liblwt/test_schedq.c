/*
 * Copyright (C) 2022 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

//  To test internal interfaces, its easiest to include the implementation
//  file and call the functions directly instead of exposing static functions
//  just for testing.

#include "lwt_sched.c"

#define	ins(name)	schedq_insert(schedq, sqix, name, name ## idix)
#define	rem()		schedq_remove(schedq, sqix)

#include <stdlib.h>
#include <stdio.h>

void errexit(const char *s)
{
	perror(s);
	exit(1);
}

int main()
{
	int error = lwt_init(0);
	if (error)
		errexit("lwt_init() failed");

	thr_t *a = thr_create_main();
	ureg_t aidix = THRID_INDEX(a->thra.thra_thrid);

	thr_t *b = thr_create_main();
	ureg_t bidix = THRID_INDEX(b->thra.thra_thrid);

	thr_t *c = thr_create_main();
	ureg_t cidix = THRID_INDEX(c->thra.thra_thrid);

	thr_t *d = thr_create_main();
	ureg_t didix = THRID_INDEX(d->thra.thra_thrid);

	thr_t *e = thr_create_main();
	ureg_t eidix = THRID_INDEX(e->thra.thra_thrid);

	thr_t *f = thr_create_main();
	ureg_t fidix = THRID_INDEX(f->thra.thra_thrid);

	thr_t *g = thr_create_main();
	ureg_t gidix = THRID_INDEX(g->thra.thra_thrid);

	thr_t *h = thr_create_main();
	ureg_t hidix = THRID_INDEX(h->thra.thra_thrid);

	schdom_t *schdom = &a->thr_core->core_hw->hw_schdom;
        schedq_t *schedq = &schdom->schdom_sqcls[a->thr_prio].sqcl_schedq;
        ureg_t sqix = schedq_index(schedq);

	thr_t *t;

	ins(a);
	ins(b);
	ins(c);
	ins(d);
	ins(e);
	ins(f);

	t = rem();
	assert(t == a);

	ins(g);
	ins(h);

	t = rem();
	assert(t == b);

	t = rem();
	assert(t == c);

	t = rem();
	assert(t == d);

	t = rem();
	assert(t == e);

	t = rem();
	assert(t == f);

	t = rem();
	assert(t == g);

	t = rem();
	assert(t == h);
}

