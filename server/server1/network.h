#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/event.h>



#include "serverbroker.h"
#include "ThreadPool.h"

class Network
{
public:
    Network();
    ~Network();

    //��ʼ������������IP�Ͷ˿�
    bool Init(std::string ip, int port);

    void Start();

    void Stop();

    //��ʼ����
    bool Listen();

    //
    bool AddListenFd();

    //����Ƿ����¼�����
    int Dispatch();

    //
    int BaseDispatch();

    //�رշ�����
    bool Close();

public:
    static struct event_base* base;
    static SSL_CTX* m_ctx;
    static ServerBroker* m_users;                //�������������

private:
    //���ܿͻ��˵���������
    bool Acceptor();

    //
    static void Acceptor(evutil_socket_t listenfd, short event, void* arg);

    //
    static void EventDispatch(evutil_socket_t fd, short events, void* arg);

    //
    static void Read(evutil_socket_t fd, short events, void* arg);

    //
    static void Write(evutil_socket_t fd, short events, void* arg);

    //��ȡ����
    bool Read(int fd);

    //д����
    bool Write(int fd);

private:
    int m_listenFd;                                 //����˼����ļ�������
    int m_epollFd;                                  //linuxʹ��epoll�������ļ�������
    std::vector<int> m_clientFd;                    //�ͻ����ļ�����������
    ThreadPool* m_pool = nullptr;                   //�̳߳ض���
   
    bool m_stop = false;
};

#endif // NETWORK_H