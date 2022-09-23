#include "network.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signal.h>
#include <iostream>

const int MAX_FD = 65535;
const int MAX_EVENTS_NUMBER = 10000;

extern void Addfd(int epollfd, int fd, bool one_shot);
extern void Removefd(int epollfd, int fd);
extern void Modefd(int epollfd, int fd, int ev);

void Addsig(int sig, void(handler)(int)){
    struct sigaction sa;
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = handler;
    sigfillset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);

}

Network::Network()
{

}

bool Network::Init(std::string ip, int port)
{
    Addsig(SIGPIPE, SIG_IGN);  //add signal handle function

    m_pool = nullptr;
    try {
        m_pool = new Threadpool<Httpconn>;
    }  catch (...) {
        exit(-1);
    }

    users = new Httpconn[MAX_FD];


    m_listenFd = socket(PF_INET, SOCK_STREAM, 0);
    if(m_listenFd == -1){
        perror("socket");
        exit(-1);
    }

    int reuse = 1;
    setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in saddr;
    saddr.sin_addr.s_addr = INADDR_ANY;
    //inet_pton(AF_INET, ip.c_str(), &saddr.sin_addr.s_addr);
    saddr.sin_port = htons(port);
    saddr.sin_family = AF_INET;
    int ret = bind(m_listenFd, (struct sockaddr *)&saddr, sizeof(saddr));
    if(ret == -1){
        perror("bind");
        exit(-1);
    }

    return  true;
}

bool Network::Listen()
{
    m_epollFd = epoll_create(100);
    if(m_epollFd == -1){
        perror("epoll_create");
        exit(-1);
    }
    int ret = listen(m_listenFd, 8);
    if(ret == -1){
        perror("listen");
        exit(-1);
    }

    Addfd(m_epollFd, m_listenFd, false);
    Httpconn::m_epollfd = m_epollFd;
    return true;
}

int Network::Dispatch()
{
    std::cout<<"dispatch"<<std::endl;
    epoll_event events[MAX_EVENTS_NUMBER];
    int num = epoll_wait(m_epollFd, events, MAX_EVENTS_NUMBER, -1);
    if((num < 0) && (errno != EINTR)){
        perror("epoll_wait");
        return -1;
    }

    for(int i = 0; i < num; i++){
        int curfd = events[i].data.fd;
        if(curfd == m_listenFd){
            Acceptor();
        }else if (events[i].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
            users[curfd].Closeconn();
        }else if(events[i].events == EPOLLIN){
            Read(curfd);
        }else if(events[i].events == EPOLLOUT){
            Write(curfd);
        }
    }
}

bool Network::Acceptor()
{
    struct sockaddr_in clientaddr;
    socklen_t len = sizeof(clientaddr);
    int clientfd = accept(m_listenFd, (struct sockaddr*)&clientaddr, &len);
    if(clientfd == -1){
        perror("accept");
        exit(-1);
    }

    if(Httpconn::m_user_count >= MAX_FD){
        //往回发送服务器连接数量过多
        close(clientfd);
        return false;
    }
    printf("tcp link\n");
    users[clientfd].Init(clientfd, clientaddr);
    return true;
}

bool Network::Read(int fd)
{
    if(users[fd].Read()){
        std::cout<<"read success\n";
        m_pool->Append(users + fd);
    }else{
        users[fd].Closeconn();
    }
}

bool Network::Write(int fd)
{
    std::cout<<"write\n"<<std::endl;
    if(!users[fd].Write()){
        users[fd].Closeconn();
    }
}

bool Network::Close()
{
    //    close(epollfd);
    //    close(listenfd);
    //    delete[] users;
    //    delete  pool;
    close(m_listenFd);
    close(m_epollFd);
    delete [] users;
    delete m_pool;

    return true;
}
