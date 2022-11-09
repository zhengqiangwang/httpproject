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

    //����post����
    virtual bool SendPost(void);

    //����get����
    virtual bool SendGet(void);

    //����get����
    bool ConstructGet();

    //����post����
    bool ConstructPost();

    //����Ϊ������
    void SetNonblocking(int fd);

    //ͨ��ip�Ͷ˿����ӷ�����
    bool LinkServer(std::string ip, int port);

    //���׽�������д���ݣ����������
    virtual bool WriteData();

    //���׽������������
    virtual int ReadData(char* outData, int readLength, bool flag);

    //�رպͷ�����������
    void CloseLink(int socketFd);

    //����epoll�ļ�������
    bool ModeEpollEvent(int epollfd, int fd, int type);
private:
    SSL_CTX* m_ctx = nullptr;
    SSL* m_ssl = nullptr;
    int m_socketFd = -1;                                                 //����׽����ļ�������
    char* m_sendContent{0};
    int m_sendLength = 0;
    int m_epollFd = -1;                                             //���epoll�ļ�������
    fd_set fdw;                                                     //���selectд�¼��ļ�������
    fd_set fdr;                                                     //���select���¼��ļ�������
};

#endif	// PLAINHTTP_H