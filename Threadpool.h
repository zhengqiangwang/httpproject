#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include <list>
#include "locker.h"
#include <boost/lockfree/queue.hpp>

template<typename T>
class Threadpool
{
public:
    Threadpool(int thread_num = 8, int max_requests = 1000);
    ~Threadpool();
    bool Append(T *request);

private:
    static void *working(void *arg);
    void run();

private:
    int m_thread_num;  //线程的数量
    pthread_t *m_threads; //线程的数组
    int m_max_request; //请求队列的最大长度
    boost::lockfree::queue<T *, boost::lockfree::capacity<1024>> m_workqueue; //请求队列
    Locker m_queuelocker; //互斥锁
    Sem m_queuestat; //通过信号量来判断是否有任务要执行
    bool m_stop; //判断是否结束线程
};

template<typename T>
Threadpool<T>::Threadpool(int thread_num, int max_requests):m_thread_num{thread_num},
    m_max_request{max_requests},m_stop{false},m_threads{nullptr}
{
    if(m_thread_num < 0 || m_max_request < 0){
        throw std::exception();
    }

    m_threads = new pthread_t[m_thread_num];
    if(!m_threads){
        throw std::exception();
    }

    for(int i = 0; i < m_thread_num; i++){
        if(pthread_create(&m_threads[i], NULL, working, this)){
            delete[] m_threads;
            throw std::exception();
        }
        if(pthread_detach(m_threads[i])){
            delete[] m_threads;
            throw std::exception();
        }
        printf("create thread %dth\n",i);
    }
}

template<typename T>
Threadpool<T>::~Threadpool(){
    delete [] m_threads;
    m_stop = true;
}

template<typename T>
bool Threadpool<T>::Append(T *request){
    m_queuelocker.lock();
    if(!m_workqueue.bounded_push(request)){
        m_queuelocker.unlock();
        return false;
    }
    printf("tid:%ld\n",pthread_self());
    m_queuelocker.unlock();
    m_queuestat.post();
    return true;
}

template<typename T>
void * Threadpool<T>::working(void *arg){
    Threadpool *pool = (Threadpool *)arg;
    pool->run();
    return pool;
}

template<typename T>
void Threadpool<T>::run(){
    while(!m_stop){
        m_queuestat.wait();
        m_queuelocker.lock();
        if(m_workqueue.empty()){
            m_queuelocker.unlock();
            continue;
        }
        T* request;
        bool result = m_workqueue.pop(request);
        m_queuelocker.unlock();

        if(!request){
            continue;
        }
        request->Process();
    }
}

#endif // THREADPOOL_H
