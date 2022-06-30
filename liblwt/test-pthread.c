
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

const char *volatile __psx_assert_file;
const char *volatile __psx_assert_msg;
int volatile __psx_assert_line;

static _Noreturn void psx_assert_fail(const char *file, int line,
				      const char *msg)
{
	__psx_assert_line = line;
	__psx_assert_msg = msg;
	__psx_assert_file = file;
	for (;;)
		*((volatile int *)11) = 0xFEEDBEEF;
}

#define	psx_assert(expr)						\
	do {								\
		if (__builtin_expect(!(expr), 0))			\
			psx_assert_fail(__FILE__, __LINE__, #expr);	\
	} while (0)

void psx_errexit(const char *s, int error)
{
	fprintf(stderr, "%s: %s\n", s, strerror(error));
	exit(1);
}

#define	PSX_QUEUE_MAX	10

typedef unsigned long	psx_data_t;

#define	PSX_DATA_LAST	((psx_data_t) ~0uL)

typedef struct {
	pthread_mutex_t	 q_mutex;
	pthread_cond_t	 q_not_empty;
	pthread_cond_t	 q_not_full;
	int		 q_first;
	int		 q_last;
	int		 q_count;
	psx_data_t	 q_data[PSX_QUEUE_MAX];
} psx_queue_t;

typedef enum { PSX_READER, PSX_WRITER } psx_kind_t;

typedef struct {
	psx_kind_t	 a_kind;
	psx_queue_t	*a_queue;
	pthread_t	 a_pthread;
	psx_data_t	 a_work;
	psx_data_t	 a_start;
	psx_data_t	 a_sum;
	psx_data_t	 a_steps;
} psx_arg_t;

int psx_queue_init(psx_queue_t *q)
{
	int error = pthread_mutex_init(&q->q_mutex, NULL);
	if (error)
		return error;

	error = pthread_cond_init(&q->q_not_empty, NULL);
	if (error)
		return error;

	error = pthread_cond_init(&q->q_not_full, NULL);
	if (error)
		return error;

	q->q_first = 0;
	q->q_last  = 0;
	q->q_count = 0;
	return 0;
}

void psx_queue_insert(psx_queue_t *q, psx_data_t data)
{
	pthread_mutex_lock(&q->q_mutex);
	while (q->q_count == PSX_QUEUE_MAX)
		pthread_cond_wait(&q->q_not_full, &q->q_mutex);
	if (q->q_count == 0)
		pthread_cond_broadcast(&q->q_not_empty);
	++q->q_count;
	q->q_data[q->q_last] = data;
	if (++q->q_last >= PSX_QUEUE_MAX)
		q->q_last = 0;
	pthread_mutex_unlock(&q->q_mutex);
}

int psx_queue_remove(psx_queue_t *q)
{
	pthread_mutex_lock(&q->q_mutex);
	while (q->q_count == 0)
		pthread_cond_wait(&q->q_not_empty, &q->q_mutex);
	if (q->q_count == PSX_QUEUE_MAX)
		pthread_cond_broadcast(&q->q_not_full);
	--q->q_count;
	int data = q->q_data[q->q_first];
	if (++q->q_first >= PSX_QUEUE_MAX)
		q->q_first = 0;
	pthread_mutex_unlock(&q->q_mutex);
	return data;
}

#define	PSX_WRITER_RETVAL	((void *) 0xDEADBEEF)

void *psx_writer(psx_arg_t *a)
{
	psx_queue_t *q = a->a_queue;
	psx_data_t data = a->a_start;
	psx_data_t inc = a->a_sum;
	psx_data_t steps = a->a_steps;
	psx_data_t i = 0;
	for (i = 0; i < steps; ++i) {
		psx_queue_insert(q, data);
		data += inc;
		++a->a_work;
	}
	psx_queue_insert(q, PSX_DATA_LAST);
	pthread_exit(PSX_WRITER_RETVAL);
}

void *psx_reader(psx_arg_t *a)
{
	psx_queue_t *q = a->a_queue;
	psx_data_t data;
	for (;;) {
		data = psx_queue_remove(q);
		if (data == PSX_DATA_LAST)
			return (void *) a->a_sum;
		a->a_sum += data;
		++a->a_work;
	}
}

#define	PSX_NREADERS	16
#define	PSX_NWRITERS	16
#define	PSX_NSTEPS	100

psx_arg_t	psx_args[PSX_NREADERS + PSX_NWRITERS];

#ifndef LWT_NOT_ON_ANDROID
#define	psx_test_main(argc, argv)	main(argc, argv)
#endif

int psx_test_main(int argc, char *argv[])
{
	int error;

	psx_data_t nsteps = PSX_NSTEPS;
	if (argc == 2)
		nsteps = atol(argv[1]);

	psx_queue_t queue;
	error = psx_queue_init(&queue);
	if (error)
		psx_errexit("psx_queue_init() failed", error);

	psx_arg_t *a = psx_args;
	int i;
	for (i = 0; i < PSX_NWRITERS; ) {
		++i;
		a->a_kind = PSX_WRITER;
		a->a_queue = &queue;
		a->a_work = 0;
		a->a_start = i;
		a->a_sum = PSX_NWRITERS;
		a->a_steps = nsteps;
		error = pthread_create(&a->a_pthread, NULL,
				       (void *(*)(void *)) psx_writer, a);
		if (error)
			psx_errexit("pthread_create() psx_writer failed",
				    error);
		++a;
	}

	for (i = 0; i < PSX_NREADERS; ) {
		a->a_kind = PSX_READER;
		a->a_queue = &queue;
		a->a_work = 0;
		a->a_start = 0;
		a->a_sum = 0;
		a->a_steps = 0;
		++i;

		if (i == PSX_NREADERS)
			break;

		error = pthread_create(&a->a_pthread, NULL,
				       (void *(*)(void *)) psx_reader, a);
		if (error)
			psx_errexit("pthread_create() psx_reader failed",
				    error);
		++a;
	}

#if 0
	const char *m = "blocking main(), return to continue it...";
	write(2, m, strlen(m));
#if 0
	char buf[100];
	read(0, buf, sizeof(buf));
#else
	pause();
#endif
#endif

	psx_data_t sum = (psx_data_t) psx_reader(a);
	a = psx_args;

	for (i = 0; i < PSX_NWRITERS; ++i) {
		void *retval;
		error = pthread_join(a->a_pthread, &retval);
		if (error)
			psx_errexit("pthread_join() psx_writer failed", error);
		psx_assert(retval == PSX_WRITER_RETVAL);
		++a;
	}

	for (i = 0; i < PSX_NREADERS - 1; ++i) {
		void *retval;
		error = pthread_join(a->a_pthread, &retval);
		if (error)
			psx_errexit("pthread_join() psx_reader failed", error);
		sum += (psx_data_t) retval;
		++a;
	}

	psx_assert(sum == (PSX_NWRITERS * nsteps) * (PSX_NWRITERS * nsteps + 1) / 2);

	exit(0);
}

