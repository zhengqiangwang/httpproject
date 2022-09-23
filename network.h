#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include "httpconn.h"
#include "Threadpool.h"

class Network
{
public:
    Network();
    bool Init(std::string ip, int port);
    bool Listen();
    int Dispatch();
    bool Acceptor();
    bool Read(int fd);
    bool Write(int fd);
    bool Close();

private:
    int m_listenFd;
    int m_epollFd;
    Httpconn *users;
    std::vector<int> m_clientFd;
    Threadpool<Httpconn> *m_pool;

};

#endif // NETWORK_H
