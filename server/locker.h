#ifndef LOCKER_H
#define LOCKER_H

#include <pthread.h>
#include <semaphore>

class Locker
{
public:
    Locker();
    ~Locker();

    bool lock();
    bool unlock();

private:
    pthread_mutex_t m_mutex;
};

class Cond
{
public:
    Cond();
    ~Cond();

    bool wait(pthread_mutex_t *mutex);
    bool timedwait(pthread_mutex_t *mutex, struct timespec *time);
    bool signal();
    bool broadcast();
private:
    pthread_cond_t m_cond;
};

class Sem
{
public:
    Sem();
    Sem(int num);
    ~Sem();

    bool wait();
    bool post();
private:
    sem_t m_sem;
};

#endif // LOCKER_H
