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

#ifndef __LWT_H_INCLUDED__ //{
#define __LWT_H_INCLUDED__

// #include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
// #include <stdbool.h>
// #include <bits/types/struct_timespec.h>
struct timespec;

//  lwt - light weight threads
//
//  This is an implementation similar to POSIX threads (pthread henceforth)
//  implemented with a user mode scheduler that can coexist with the
//  native pthread implementation.  Error prone areas of pthreads have been
//  improved upon (signals and broadcasts of condition variables without
//  holding the associated mutex are not allowed), which leads to simpler
//  and faster code, while reducing programming errors.

int __lwt_init(size_t sched_attempt_steps);

static inline int lwt_init(size_t sched_attempt_steps)
{
	return __lwt_init(sched_attempt_steps);
}


//  A light weight thread ID, represented as a pointer to an undefined
//  structure, this prevents arithmetic on values of this type, it also
//  prevents type confusion between values of this type and values of any
//  other type (other than expressions of (void *) type).

typedef uintptr_t lwt_t;


//  The memory for the implementation of threads and synchronizers is kept
//  segregated from application memory to ensure that:
//
//    - It is locked in memory (prevented from being paged out); and
//    - Its implementation details are hidden from the application;
//
//  The types used by the application for lwt_mutex_t and lwt_cond_t are
//  structures that contain pointers to the implementation memory.
//
//  The lwt_mutex_init(), lwt_mutex_destroy(), lwt_cond_init() and
//  lwt_cond_destroy() functions require pointers to the lwt_mutex_t and
//  lwt_cond_t types, respectively, so that the pointer in them can be set
//  and cleared at initialization and destruction time.
//
//  All other lwt_mutex_*() and lwt_cond_*()functions work on the
//  implementation type that the pointer points to, they don't require access
//  to the lwt_mutex_t or lwt_cond_t types, they are all inline functions
//  that call the implementation function after fetching the implementation
//  pointer, doing this on the application function prevents needless
//  pointer computations and moves the fetching of the pointer value away
//  from its use, increasing the fetch-to-use distance by including the
//  function call and function entry thus reducing the performance effects
//  of this extra level of indirection.
//
//  The implementation functions and types have names similar to the API
//  functions with a double underscore prefix and the name of the type
//  adjusted, for example:
//      lwt_mutex_lock() => __lwt_mtx_lock()


//  lwt_mutexattr_t

struct __lwt_mtxattr_s;

typedef struct {
	struct __lwt_mtxattr_s	*mtxattr;
} lwt_mutexattr_t;

int __lwt_mtxattr_init(		struct __lwt_mtxattr_s **mtxattrpp);
int __lwt_mtxattr_destroy(	struct __lwt_mtxattr_s **mtxattrpp);
int __lwt_mtxattr_settype(	struct __lwt_mtxattr_s **mtxattrpp, int kind);
int __lwt_mtxattr_gettype(	const struct __lwt_mtxattr_s *mtxattr,
				int *kind);

static inline int lwt_mutexttr_init(lwt_mutexattr_t *mutexattr)
{
	return __lwt_mtxattr_init(&mutexattr->mtxattr);
}

static inline int lwt_mutexttr_destroy(lwt_mutexattr_t *mutexattr)
{
	return __lwt_mtxattr_destroy(&mutexattr->mtxattr);
}

typedef enum {
	LWT_MTX_FAST = 0,	//  Self deadlocks if recursively locked,
				//  must be zero to coincide with NULL default
				//  lwt_mutexattr_t * pointer value.

	LWT_MTX_ERRORCHECK = 1,	//  Returns EDEADLK instead of self deadlock
	LWT_MTX_RECURSIVE = 2,	//  Recursive lock/unlock supported
	LWT_MTX_LAST = LWT_MTX_RECURSIVE 
} lwt_mtx_type_t;

static inline int lwt_mutexattr_settype(lwt_mutexattr_t *mutexattr, int kind)
{
	return __lwt_mtxattr_settype(&mutexattr->mtxattr, kind);
}

static inline int lwt_mutexattr_gettype(const lwt_mutexattr_t *mutexattr,
					int *kind)
{
	return __lwt_mtxattr_gettype(mutexattr->mtxattr, kind);
}


//  lwt_mutex_t

struct __lwt_mtx_s;

int __lwt_mtx_init(	struct __lwt_mtx_s		**mtxpp,
			const struct __lwt_mtxattr_s	 *mtxattr);
int __lwt_mtx_destroy(	struct __lwt_mtx_s		**mtxpp);
int __lwt_mtx_lock(	struct __lwt_mtx_s		 *mtx);
int __lwt_mtx_trylock(	struct __lwt_mtx_s		 *mtx);
int __lwt_mtx_unlock(	struct __lwt_mtx_s		 *mtx);

typedef struct {
	struct __lwt_mtx_s	*mtx;
} lwt_mutex_t;

static inline int lwt_mutex_init(lwt_mutex_t *mutex,
				 const lwt_mutexattr_t *mutexattr)
{
	return __lwt_mtx_init(&mutex->mtx,
			      mutexattr ? mutexattr->mtxattr : NULL);
}

static inline int lwt_mutex_destroy(lwt_mutex_t *mutex)
{
	return __lwt_mtx_destroy(&mutex->mtx);
};

static inline int lwt_mutex_lock(lwt_mutex_t *mutex)
{
	return __lwt_mtx_lock(mutex->mtx);
}

static inline int lwt_mutex_trylock(lwt_mutex_t *mutex)
{
	return __lwt_mtx_trylock(mutex->mtx);
}

static inline int lwt_mutex_unlock(lwt_mutex_t *mutex)
{
	return __lwt_mtx_unlock(mutex->mtx);
}


//  lwt_cond_t

struct __lwt_cnd_s;
struct __lwt_cndattr_s;

int __lwt_cnd_init(	struct __lwt_cnd_s		**cndpp,
			const struct __lwt_cndattr_s	 *cndattr);
int __lwt_cnd_destroy(	struct __lwt_cnd_s		**cndpp);
int __lwt_cnd_wait(	struct __lwt_cnd_s		 *cnd,
			struct __lwt_mtx_s		 *mtx);
int __lwt_cnd_timedwait(struct __lwt_cnd_s		 *cnd,
			struct __lwt_mtx_s		 *mtx,
			const struct timespec		 *abstime);
int __lwt_cnd_signal(	struct __lwt_cnd_s		 *cnd,
			struct __lwt_mtx_s		 *mtx);
int __lwt_cnd_broadcast(struct __lwt_cnd_s		 *cnd,
			struct __lwt_mtx_s		 *mtx);

typedef struct {
	struct __lwt_cnd_s	*cnd;
} lwt_cond_t;

typedef struct {
	struct __lwt_cndattr_s	*cndattr;
} lwt_condattr_t;

static inline int lwt_cond_init(lwt_cond_t *cond, lwt_condattr_t *condattr)
{
	return __lwt_cnd_init(&cond->cnd,
			      condattr ? condattr->cndattr : NULL);
}

static inline int lwt_cond_destroy(lwt_cond_t *cond)
{
	return __lwt_cnd_destroy(&cond->cnd);
}

static inline int lwt_cond_wait(lwt_cond_t *cond, lwt_mutex_t *mutex)
{
	return __lwt_cnd_wait(cond->cnd, mutex->mtx);
}

static inline int lwt_cond_timedwait(lwt_cond_t *cond, lwt_mutex_t *mutex,
		       const struct timespec *abstime)
{
	return __lwt_cnd_timedwait(cond->cnd, mutex->mtx, abstime);
}

static inline int lwt_cond_signal(lwt_cond_t *cond, lwt_mutex_t *mutex)
{
	return __lwt_cnd_signal(cond->cnd, mutex->mtx);
}

static inline int lwt_cond_broadcast(lwt_cond_t *cond, lwt_mutex_t *mutex)
{
	return __lwt_cnd_broadcast(cond->cnd, mutex->mtx);
}


//  The memory for the implementation of spinlocks (lwt_spinlock_t) is
//  under control of the application, the spinlock is not kept out-of-line
//  in other memory (as is done for lwt_mutex_t and lwt_cond_t, see below)
//  because lwt_spinlock_t are strictly spinning and don't compound in any
//  way with other synchronizers, there are no complex interactions between
//  them and scheduling or waiting for conditions to occur.

//  lwt_spinlock_t

struct __lwt_spin_s {
	uintptr_t	spin_mem;
};

typedef struct {
	struct __lwt_spin_s	spin;
} lwt_spinlock_t;

int __lwt_spin_init(	struct __lwt_spin_s	*spin);
int __lwt_spin_destroy(	struct __lwt_spin_s	*spin);
int __lwt_spin_lock(	struct __lwt_spin_s	*spin);
int __lwt_spin_trylock(	struct __lwt_spin_s	*spin);
int __lwt_spin_unlock(	struct __lwt_spin_s	*spin);

static inline int lwt_spin_init(lwt_spinlock_t	*spinlock)
{
	return __lwt_spin_init(&spinlock->spin);
}

static inline int lwt_spin_destroy(lwt_spinlock_t *spinlock)
{
	return __lwt_spin_destroy(&spinlock->spin);
}

static inline int lwt_spin_lock(lwt_spinlock_t *spinlock)
{
	return __lwt_spin_lock(&spinlock->spin);
}

static inline int lwt_spin_trylock(lwt_spinlock_t *spinlock)
{
	return __lwt_spin_trylock(&spinlock->spin);
}

static inline int lwt_spin_unlock(lwt_spinlock_t *spinlock)
{
	return __lwt_spin_unlock(&spinlock->spin);
}


//  Default values for thread creation unless overriden via a lwt_attr_t,
//  are the zero values below.

typedef enum {
	LWT_CREATE_JOINABLE = 0,
	LWT_CREATE_DETACHED = 1,
	LWT_CREATE_LAST     = LWT_CREATE_DETACHED 
} lwt_thr_detach_t;

typedef enum {
	LWT_SCOPE_PROCESS = 0,
	LWT_SCOPE_SYSTEM  = 1,
	LWT_SCOPE_LAST    = LWT_SCOPE_SYSTEM
} lwt_thr_scope_t;

typedef enum {
	LWT_INHERIT_SCHED     = 0,
	LWT_EXPLICIT_SCHED    = 1,
	LWT_INHERITSCHED_LAST = LWT_EXPLICIT_SCHED
} lwt_thr_inheritsched_t;

typedef enum {
	LWT_SCHED_OTHER = 0,
	LWT_SCHED_FIFO  = 1,
	LWT_SCHED_RR    = 2,
	LWT_SCHED_LAST  = LWT_SCHED_RR    
} lwt_thr_schedpolicy_t;

typedef enum {
	LWT_PRIO_LOW  = 0,
	LWT_PRIO_MID  = 15,
	LWT_PRIO_HIGH = 31
} lwt_thr_prio_t;


//  lwt_thrattr_t

typedef struct __lwt_attr_s {
	void			*pad[8];
} lwt_attr_t;

typedef struct lwt_sched_param {
	int	sched_priority;
} lwt_sched_param_t;

int __lwt_thrattr_init(		  lwt_attr_t		  *attr);
int __lwt_thrattr_destroy(	  lwt_attr_t		  *attr);
#if 0
int __lwt_thrattr_setsigmask_np(  lwt_attr_t		  *attr,
				  const sigset_t	  *sigmask);
int __lwt_thrattr_getsigmask_np(  const lwt_attr_t	  *attr,
				  sigset_t		  *sigmask);
#endif
int __lwt_thrattr_setdetachstate( lwt_attr_t		  *attr,
				  int			   detachstate);
int __lwt_thrattr_getdetachstate( const lwt_attr_t	  *attr,
				  int			  *detachstate);
#if 0
int __lwt_thrattr_setaffinity_np( lwt_attr_t 		  *attr,
				  size_t		   cpusetsize,
				  const cpu_set_t	  *cpuset);
int __lwt_thrattr_getaffinity_np( const lwt_attr_t	  *attr,
				  size_t		   cpusetsize,
				  cpu_set_t		  *cpuset);
#endif
int __lwt_thrattr_setscope(	  lwt_attr_t 		  *attr,
				  int			   scope);
int __lwt_thrattr_getscope(	  const lwt_attr_t	  *attr,
				  int			  *scope);
int __lwt_thrattr_setschedpolicy( lwt_attr_t 		  *attr,
				  int			   policy);
int __lwt_thrattr_getschedpolicy( const lwt_attr_t	  *attr,
				  int			  *policy);
int __lwt_thrattr_setinheritsched(lwt_attr_t		  *attr,
				  int			   inheritsched);
int __lwt_thrattr_getinheritsched(const lwt_attr_t	  *attr,
				  int			  *inheritsched);
int __lwt_thrattr_setschedparam(  lwt_attr_t 		  *attr,
				  const lwt_sched_param_t *param);
int __lwt_thrattr_getschedparam(  const lwt_attr_t	  *attr,
				  lwt_sched_param_t	  *param);
int __lwt_thrattr_setstack(	  lwt_attr_t 		  *attr,
				  void			  *stackaddr,
				  size_t		   stacksize);
int __lwt_thrattr_getstack(	  const lwt_attr_t	  *attr,
				  void			 **stackaddr,
				  size_t		  *stacksize);
int __lwt_thrattr_setstacksize(	  lwt_attr_t 		  *attr,
				  size_t		   stacksize);
int __lwt_thrattr_getstacksize(	  const lwt_attr_t	  *attr,
				  size_t		   *stacksize);
int __lwt_thrattr_setstackaddr(	  lwt_attr_t 		  *attr,
				  void			  *stackaddr);
int __lwt_thrattr_getstackaddr(	  const lwt_attr_t	  *attr,
				  void			 **stackaddr);
int __lwt_thrattr_setguardsize(	  lwt_attr_t 		  *attr,
				  size_t		   guardsize);
int __lwt_thrattr_getguardsize(	  const lwt_attr_t	  *attr,
				  size_t		  *guardsize);

static inline int lwt_attr_init(lwt_attr_t *attr)
{
	return __lwt_thrattr_init(attr);
}

static inline int lwt_attr_destroy(lwt_attr_t *attr)
{
	return __lwt_thrattr_destroy(attr);
}

#if 0
static inline int lwt_attr_setsigmask_np(lwt_attr_t *attr,
					 const sigset_t *sigmask)
{
	return __lwt_thrattr_setsigmask_np(attr, sigmask);
}

static inline int lwt_attr_getsigmask_np(const lwt_attr_t *attr,
					 sigset_t *sigmask)
{
	return __lwt_thrattr_getsigmask_np(attr, sigmask);
}
#endif

static inline int lwt_attr_setdetachstate(lwt_attr_t *attr, int detachstate)
{
	return __lwt_thrattr_setdetachstate(attr, detachstate);
}

static inline int lwt_attr_getdetachstate(const lwt_attr_t *attr,
					  int *detachstate)
{
	return __lwt_thrattr_getdetachstate(attr, detachstate);
}

#if 0
static inline int lwt_attr_setaffinity_np(lwt_attr_t *attr,
				   size_t cpusetsize, const cpu_set_t *cpuset)
{
	return __lwt_thrattr_setaffinity_np(attr, cpusetsize, cpuset);
}

static inline int lwt_attr_getaffinity_np(const lwt_attr_t *attr,
				   size_t cpusetsize, cpu_set_t *cpuset)
{
	return __lwt_thrattr_getaffinity_np(attr, cpusetsize, cpuset);
}
#endif

static inline int lwt_attr_setscope(lwt_attr_t *attr, int scope)
{
	return __lwt_thrattr_setscope(attr, scope);
}

static inline int lwt_attr_getscope(const lwt_attr_t *attr, int *scope)
{
	return __lwt_thrattr_getscope(attr, scope);
}

static inline int lwt_attr_setschedpolicy(lwt_attr_t *attr, int policy)
{
	return __lwt_thrattr_setschedpolicy(attr, policy);
}

static inline int lwt_attr_getschedpolicy(const lwt_attr_t *attr, int *policy)
{
	return __lwt_thrattr_getschedpolicy(attr, policy);
}

static inline int lwt_attr_setinheritsched(lwt_attr_t *attr, int inheritsched)
{
	return __lwt_thrattr_setinheritsched(attr, inheritsched);
}

static inline int lwt_attr_getinheritsched(const lwt_attr_t *attr,
					   int *inheritsched)
{
	return __lwt_thrattr_getinheritsched(attr, inheritsched);
}

static inline int lwt_attr_setschedparam(lwt_attr_t *attr,
				  const lwt_sched_param_t *param)
{
	return __lwt_thrattr_setschedparam(attr, param);
}

static inline int lwt_attr_getschedparam(const lwt_attr_t *attr,
				  lwt_sched_param_t *param)
{
	return __lwt_thrattr_getschedparam(attr, param);
}

static inline int lwt_attr_setstack(lwt_attr_t *attr,
			     void *stackaddr, size_t stacksize)
{
	return __lwt_thrattr_setstack(attr, stackaddr, stacksize);
}

static inline int lwt_attr_getstack(const lwt_attr_t *attr,
		      void **stackaddr, size_t *stacksize)
{
	return __lwt_thrattr_getstack(attr, stackaddr, stacksize);
}

static inline int lwt_attr_setstacksize(lwt_attr_t *attr, size_t stacksize)
{
	return __lwt_thrattr_setstacksize(attr, stacksize);
}

static inline int lwt_attr_getstacksize(const lwt_attr_t *attr,
					size_t *stacksize)
{
	return __lwt_thrattr_getstacksize(attr, stacksize);
}

static inline int lwt_attr_setstackaddr(lwt_attr_t *attr, void *stackaddr)
{
	return __lwt_thrattr_setstackaddr(attr, stackaddr);
}

static inline int lwt_attr_getstackaddr(const lwt_attr_t *attr,
					void **stackaddr)
{
	return __lwt_thrattr_getstackaddr(attr, stackaddr);
}

static inline int lwt_attr_setguardsize(lwt_attr_t *attr, size_t guardsize)
{
	return __lwt_thrattr_setguardsize(attr, guardsize);
}

static inline int lwt_attr_getguardsize(const lwt_attr_t *attr,
					size_t *guardsize)
{
	return __lwt_thrattr_getguardsize(attr, guardsize);
}


//  lwt_t

typedef enum {
       LWT_CANCEL_ENABLE = 0,
       LWT_CANCEL_DISABLE = 1
} lwt_cancel_state_t;

typedef enum {
       LWT_CANCEL_DEFERRED = 0,
       LWT_CANCEL_ASYNCHRONOUS = 1
} lwt_cancel_type_t;

typedef void *(*lwt_function_t)(void *arg);

int  __lwt_thr_create(		lwt_t		 *thread,
				const lwt_attr_t *thrattr,
				lwt_function_t	  function,
				void		 *arg);
void _Noreturn __lwt_thr_exit(	void		 *retval);
int  __lwt_thr_join(		lwt_t		  thread,
				void		**retval);
int  __lwt_thr_cancel(		lwt_t		  thread);
int  __lwt_thr_setcancelstate(	int		  state,
				int		 *oldstate);
int  __lwt_thr_setcanceltype(	int		  type,
				int		 *oldtype);
void __lwt_thr_testcancel(void);

static inline int lwt_create(lwt_t *thread, const lwt_attr_t *attr,
		      lwt_function_t function, void *arg)
{
	return __lwt_thr_create(thread, attr, function, arg);
}

static _Noreturn inline void lwt_exit(void *retval)
{
	__lwt_thr_exit(retval);
}

static inline int lwt_join(lwt_t thread, void **retval)
{
	return __lwt_thr_join(thread, retval);
}

static inline int lwt_cancel(lwt_t thread)
{
	return __lwt_thr_cancel(thread);
}

static inline int lwt_setcancelstate(int state, int *oldstate)
{
	return __lwt_thr_setcancelstate(state, oldstate);
}

static inline int lwt_setcanceltype(int type, int *oldtype)
{
	return __lwt_thr_setcanceltype(type, oldtype);
}

static inline void lwt_testcancel(void)
{
	__lwt_thr_testcancel();
}

#define lwt_cleanup_push(routine, arg)					\
	do {								\
		lwt_cleanup __lwt_cleanup_record = {			\
			.lwt_cleanup_routine = (routine),		\
			.lwt_cleanup_arg = (arg)			\
		};							\
		lwt_cleanup_push(&__lwt_cleanup_record)

#define	lwt_cleanup_pop(execute)					\
		lwt_cleanup_pop(&__lwt_cleanup_record, execute);	\
	} while (0)


//  lwt_key_t is represented as a pointer to an undefined structure, this
//  prevents arithmetic on values of this type, it also prevents type
//  confusion between values of this type and values of any other type
//  (other than expressions of (void *) type).

typedef struct lwt_key_undefined_s	 *lwt_key_t;

int   __lwt_key_create(	lwt_key_t	 *key,
			void		(*destr_function)(void *));
int   __lwt_key_delete(	lwt_key_t	  key);
int   __lwt_setspecific(lwt_key_t	  key,
			const void	 *pointer);
void *__lwt_getspecific(lwt_key_t	  key);

static inline int lwt_key_create(lwt_key_t *key,
				 void (*destr_function) (void *))
{
	return __lwt_key_create(key, destr_function);
}

static inline int lwt_key_delete(lwt_key_t key)
{
	return __lwt_key_delete(key);
}

static inline int lwt_setspecific(lwt_key_t key, const void *pointer)
{
	return __lwt_setspecific(key, pointer);
}

static inline void *lwt_getspecific(lwt_key_t key)
{
	return __lwt_getspecific(key);
}

#endif //} __LWT_H_INCLUDED__
