#include "addons.h"

int sched_getaffinity (pthread_t _th, size_t _ss, cpu_set_t* _s)
{
    return
    syscall(__NR_sched_getaffinity, _th, _ss, _s);
}

int sched_setaffinity (pthread_t _th, size_t _ss, const cpu_set_t* _s)
{
    return
    syscall(__NR_sched_setaffinity, _th, _ss, _s);
}

int sem_get( key_t __key, int __nsems, int __fl)
{
    return
    syscall( __NR_semget, __key, __nsems, __fl);
}

int sem_op( int __semid, struct sembuf* __sb, unsigned __sop)
{
    return
    syscall( __NR_semop, __semid, __sb, __sop);
}

int sem_set(int __semid, int __semnum, int __val)
{
    return
    syscall(__NR_semctl, __semid, __semnum, SETVAL, __val);
}

