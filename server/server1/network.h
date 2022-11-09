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

    //初始化服务器监听IP和端口
    bool Init(std::string ip, int port);

    void Start();

    void Stop();

    //开始监听
    bool Listen();

    //
    bool AddListenFd();

    //监测是否有事件发送
    int Dispatch();

    //
    int BaseDispatch();

    //关闭服务器
    bool Close();

public:
    static struct event_base* base;
    static SSL_CTX* m_ctx;
    static ServerBroker* m_users;                //服务器代理对象

private:
    //接受客户端的连接请求
    bool Acceptor();

    //
    static void Acceptor(evutil_socket_t listenfd, short event, void* arg);

    //
    static void EventDispatch(evutil_socket_t fd, short events, void* arg);

    //
    static void Read(evutil_socket_t fd, short events, void* arg);

    //
    static void Write(evutil_socket_t fd, short events, void* arg);

    //读取数据
    bool Read(int fd);

    //写数据
    bool Write(int fd);

private:
    int m_listenFd;                                 //服务端监听文件描述符
    int m_epollFd;                                  //linux使用epoll监听的文件描述符
    std::vector<int> m_clientFd;                    //客户端文件描述符集合
    ThreadPool* m_pool = nullptr;                   //线程池对象
   
    bool m_stop = false;
};

#endif // NETWORK_H