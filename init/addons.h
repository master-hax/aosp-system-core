#ifndef __INIT_ADDONS_H
#define __INIT_ADDONS_H

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <linux/sem.h>
#include <asm/unistd.h>


/* Size definition for CPU sets.  */
# define __CPU_SETSIZE  32
# define __NCPUBITS     (8 * sizeof (__cpu_mask))

/* Type for array elements in 'cpu_set_t'.  */
typedef unsigned long int __cpu_mask;

/* Basic access functions.  */
# define __CPUELT(cpu)  ((cpu) / __NCPUBITS)
# define __CPUMASK(cpu) ((__cpu_mask) 1 << ((cpu) % __NCPUBITS))

/* Data structure to describe CPU mask.  */
typedef struct
{
  __cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];
} cpu_set_t;


int sched_getaffinity(pthread_t _th, size_t __ss, cpu_set_t* _s);
int sched_setaffinity(pthread_t _th, size_t __ss, const cpu_set_t* _s);
int sem_get(key_t __key, int __nsems, int __fl);
int sem_op(int __semid, struct sembuf* __sb, unsigned __sop);
int sem_set(int __semid, int __semnum, int __val);

#endif //__INIT_ADDONS_H


