#pragma once
#ifndef PLAINHTTP_H
#define PLAINHTTP_H

#include <string>
#include <openssl/ssl.h>
#include "http.h"

class PlainHttp : public Http
{
public:
    PlainHttp();

    ~PlainHttp();

    //发送post请求
    virtual bool SendPost(void);

    //发送get请求
    virtual bool SendGet(void);

    //构造get请求
    bool ConstructGet();

    //构造post请求
    bool ConstructPost();

    //设置为非阻塞
    void SetNonblocking(int fd);

    //通过ip和端口连接服务器
    bool LinkServer(std::string ip, int port);

    //往套接字里面写数据，发往服务端
    virtual bool WriteData();

    //从套接字里面读数据
    virtual int ReadData(char* outData, int readLength, bool flag);

    //关闭和服务器的连接
    void CloseLink(int socketFd);

    //更改epoll文件描述符
    bool ModeEpollEvent(int epollfd, int fd, int type);
private:
    SSL_CTX* m_ctx = nullptr;
    SSL* m_ssl = nullptr;
    int m_socketFd = -1;                                                 //存放套接字文件描述符
    char* m_sendContent{0};
    int m_sendLength = 0;
    int m_epollFd = -1;                                             //存放epoll文件描述符
    fd_set fdw;                                                     //存放select写事件文件描述符
    fd_set fdr;                                                     //存放select读事件文件描述符
};

#endif	// PLAINHTTP_H