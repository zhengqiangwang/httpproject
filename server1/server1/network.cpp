#include "network.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <csignal>
#include <event2/thread.h>
#include "define.h"

#ifdef WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signal.h>
#endif

struct event_base* Network::base = nullptr;
SSL_CTX* Network::m_ctx = nullptr;
ServerBroker* Network::m_users = nullptr;                //服务器代理对象
std::map<std::string, ServerBrokerPtr> Network::ConnectionMap;

const int MAX_FD = FD_SETSIZE;
const int MAX_EVENTS_NUMBER = 10000;

extern void AddSelectFd(fd_set &selectFd, int fd);
extern void RemoveSelectFd(fd_set &selectFd, int fd);
extern void Addfd(int epollfd, int fd, bool one_shot);
extern void Removefd(int epollfd, int fd);
extern void Modefd(int epollfd, int fd, int ev);

#ifndef WIN32
void Addsig(int sig, void(handler)(int)) {
    struct sigaction sa;
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = handler;
    sigfillset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);

}
#endif

Network::Network()
{

}

Network::~Network()
{
    SSL_CTX_free(m_ctx);
    event_base_free(base);
    Close();
}
bool Network::Init(std::string ip, int port)
{
#ifndef WIN32
    Addsig(SIGPIPE, SIG_IGN);  //add signal handle function
#endif

    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    m_ctx = SSL_CTX_new(TLS_server_method()); //TLSv1_2_server_method() SSLv23_server_method()
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
    if (m_ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return false;
    }

    // 双向验证
    // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(m_ctx, CLIENT_CA_FILE, NULL) <= 0) {
        ERR_print_errors_fp(stdout);
        return false;
    }

    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(m_ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return false;
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(m_ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return false;
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(m_ctx)) {
        ERR_print_errors_fp(stdout);
        return false;
    }


    m_pool = nullptr;
    try {
        int threadPoolSize = std::thread::hardware_concurrency() * 2;
        m_pool = new ThreadPool(threadPoolSize);
    }
    catch (...) {
        exit(-1);
    }

    m_users = new ServerBroker[MAX_FD];


    m_listenFd = socket(PF_INET, SOCK_STREAM, 0);
    if (m_listenFd == -1) {
        perror("socket");
        exit(-1);
    }

    int reuse = 1;
    setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, (const char *) & reuse, sizeof(reuse));

    struct sockaddr_in saddr;
    saddr.sin_addr.s_addr = INADDR_ANY;
    //inet_pton(AF_INET, ip.c_str(), &saddr.sin_addr.s_addr);
    saddr.sin_port = htons(port);
    saddr.sin_family = AF_INET;
    int ret = bind(m_listenFd, (struct sockaddr*)&saddr, sizeof(saddr));
    if (ret == -1) {
        perror("bind");
        exit(-1);
    }

    return  true;
}

void Network::Start()
{
    Listen();
    /*AddListenFd();
    while (!m_stop)
    {
        Dispatch();
    }*/

    BaseDispatch();
}

void Network::Stop()
{
    //m_stop = true;

    event_base_loopbreak(base);

    Close();
}

bool Network::Listen()
{
    int ret = listen(m_listenFd, 8);
    if (ret == -1) {
        perror("listen");
        exit(-1);
    }

    
    return true;
}

bool Network::AddListenFd()
{
#ifdef WIN32
    AddSelectFd(ServerBroker::m_fdRead, m_listenFd);
#else
    m_epollFd = epoll_create(100);
    if (m_epollFd == -1) {
        perror("epoll_create");
        exit(-1);
    }
    Addfd(m_epollFd, m_listenFd, false);
    ServerBroker::m_epollFd = m_epollFd;
#endif
    return false;
}

int Network::Dispatch()
{
    //std::cout << "dispatch --------" << std::endl;
#ifdef WIN32
    fd_set setwrite;
    fd_set setread;
    fd_set setexcept;
    FD_ZERO(&setwrite);
    FD_ZERO(&setread);
    FD_ZERO(&setexcept);
    int max = 0;
    for (int i = 0; i < FD_SETSIZE; i++)
    {
        if (FD_ISSET(i, &ServerBroker::m_fdWrite))
        {
            //std::cout << "select write fd:" << i << std::endl;
            FD_SET(i, &setwrite);
            if (i > max)
            {
                max = i;
            }
        }
        if (FD_ISSET(i, &ServerBroker::m_fdRead))
        {
            //std::cout << "select read fd:" << i << std::endl;
            FD_SET(i, &setread);
            if (i > max)
            {
                max = i;
            }
        }
        if (FD_ISSET(i, &ServerBroker::m_fdException))
        {
            FD_SET(i, &setexcept);
            if (i > max)
            {
                max = i;
            }
        }
    }
    struct timeval time_val;
    time_val.tv_sec = 0;
    time_val.tv_usec = 2;
    fd_set fdw;
    FD_ZERO(&fdw);
    FD_SET(m_listenFd, &fdw);
    int setresult = select(0, &setread, &setwrite, &setexcept, &time_val);
    //std::cout << "select result:" << setresult << std::endl;
    if (!setresult)
    {
        return 0;
    }

    for (int i = 0; i <= FD_SETSIZE; i++)
    {
        if (i == m_listenFd && FD_ISSET(i, &setread))
        {
            Acceptor();
            continue;
        }
        if (FD_ISSET(i, &setwrite))
        {
            Write(i);
            std::cout << "write data success" << std::endl;
            RemoveSelectFd(ServerBroker::m_fdWrite, i);
        }
        if (FD_ISSET(i, &setread))
        {
            std::cout << "from socket read data" << std::endl;
            Read(i);
            //(ServerBroker::m_fdRead, i);
        }
        if (FD_ISSET(i, &setexcept))
        {
            RemoveSelectFd(ServerBroker::m_fdException, i);
            continue;
        }
    }
#else

    std::cout << "dispatch" << std::endl;
    epoll_event events[MAX_EVENTS_NUMBER];
    int num = epoll_wait(m_epollFd, events, MAX_EVENTS_NUMBER, -1);
    if ((num < 0) && (errno != EINTR)) {
        perror("epoll_wait");
        return -1;
    }

    for (int i = 0; i < num; i++) {
        int curfd = events[i].data.fd;
        if (curfd == m_listenFd) {
            Acceptor();
        }
        else if (events[i].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
            m_users[curfd].CloseConnection();
        }
        else if (events[i].events == EPOLLIN) {
            Read(curfd);
        }
        else if (events[i].events == EPOLLOUT) {
            Write(curfd);
        }
    }
#endif
}

int Network::BaseDispatch()
{
#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif
    struct event* listener_event;
    base = event_base_new();
    if (!base)
    {
        return -1;
    }

    listener_event = event_new(base, m_listenFd, EV_READ | EV_PERSIST, Acceptor, (void*)base);
    event_add(listener_event, NULL);
    event_base_dispatch(base);
    return 0;
}

bool Network::Acceptor()
{
    std::cout << "acceptor" << std::endl;
    struct sockaddr_in clientaddr;
    socklen_t len = sizeof(clientaddr);
    int clientfd = accept(m_listenFd, (struct sockaddr*)&clientaddr, &len);
    if (clientfd == -1) {
        perror("accept");
        exit(-1);
    }

    char pip[17];
    memset(pip, 0, 17);
    inet_ntop(AF_INET, &clientaddr.sin_addr.s_addr, pip, 17);
    std::string ip = pip;

    bool strict = false;
    if (ServerBroker::m_restrictIp.count(ip))
    {
        int second = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(ServerBroker::m_restrictIp[ip].time_since_epoch()).count();
        if (second < STRICTTIME)
        {
            strict = true;
            auto &n = ServerBroker::m_restrictIp[ip];
            n = std::chrono::steady_clock::now();

        }
        else
        {
            ServerBroker::m_restrictIp.erase(ServerBroker::m_restrictIp.find(ip));
        }
    }

    if (clientfd > MAX_FD || ServerBroker::m_userCount >= MAX_FD || strict) {
        //往回发送服务器连接数量过多
#ifdef WIN32
        closesocket(clientfd);
#else
        close(clientfd);
#endif
        return false;
    }
    printf("tcp link\n");
    ServerBrokerPtr broker(new(ServerBroker));
    ConnectionMap[std::to_string(clientfd)] = broker;
    broker->Init(clientfd, clientaddr, &m_ctx);
    //m_users[clientfd].Init(clientfd, clientaddr, &m_ctx);
    std::cout << "aaccept clientfd:" << clientfd << std::endl;
    //AddSelectFd(ServerBroker::m_fdRead, clientfd);    
    return true;
}

void Network::Acceptor(evutil_socket_t listenfd, short event, void* arg)
{
    std::cout << "acceptor" << std::endl;
    struct sockaddr_in clientaddr;
    socklen_t len = sizeof(clientaddr);
    int clientfd = accept(listenfd, (struct sockaddr*)&clientaddr, &len);
    if (clientfd == -1) {
        perror("accept");
        exit(-1);
    }

    char pip[17];
    memset(pip, 0, 17);
    inet_ntop(AF_INET, &clientaddr.sin_addr.s_addr, pip, 17);
    std::string ip = pip;

    bool strict = false;
    if (ServerBroker::m_restrictIp.count(ip))
    {
        int second = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(ServerBroker::m_restrictIp[ip].time_since_epoch()).count();
        if (second < STRICTTIME)
        {
            strict = true;
            auto& n = ServerBroker::m_restrictIp[ip];
            n = std::chrono::steady_clock::now();

        }
        else
        {
            ServerBroker::m_restrictIp.erase(ServerBroker::m_restrictIp.find(ip));
        }
    }

    if (clientfd > MAX_FD || ServerBroker::m_userCount >= MAX_FD || strict) {
        //往回发送服务器连接数量过多
#ifdef WIN32
        closesocket(clientfd);
#else
        close(clientfd);
#endif
        return;
    }

    std::cout << clientfd << std::endl;
    if (ConnectionMap.count(std::to_string(clientfd)))
    {
        ConnectionMap.erase(ConnectionMap.find(std::to_string(clientfd)));
        std::cout << "erase" << std::endl;
    }
    
    if (ConnectionMap.count(std::to_string(clientfd)))
    {
        std::cout << "aready delete" << std::endl;
        ConnectionMap[std::to_string(clientfd)]->Init(clientfd, clientaddr, &m_ctx);
    }
    else
    {
        ServerBrokerPtr broker(new(ServerBroker));
        ConnectionMap[std::to_string(clientfd)] = broker;
        broker->Init(clientfd, clientaddr, &m_ctx);
    }
    
    //m_users[clientfd].Init(clientfd, clientaddr, &m_ctx);
    struct event* ev = event_new(base, clientfd, EV_READ, Read, event_self_cbarg());
    //将动态创建的结构体作为event的回调参数
    event_add(ev, NULL);

    ConnectionMap[std::to_string(clientfd)]->SetEvent(ev, Read, EventDispatch);
    //m_users[clientfd].SetEvent(ev, Read, EventDispatch);

}

void Network::EventDispatch(evutil_socket_t fd, short events, void* arg)
{

    if (events & EV_READ)
    {
        Read(fd, events, arg);
    }
    if (events & EV_WRITE)
    {
        Write(fd, events, arg);
    }
}

void Network::Read(evutil_socket_t fd, short events, void* arg)
{
    /*struct event* event = (struct event*)arg;
    short r = event_get_events(event);
    if (r & EV_READ)
    {
        std::cout << "network start EV_READ" << std::endl;
    }
    if (r & EV_WRITE)
    {
        std::cout << "network start EV_WRITE" << std::endl;
    }*/
    ConnectionMap[std::to_string(fd)]->ReadData();
    //m_users[fd].ReadData();
  /*  r = event_get_events(event);
    if (r & EV_READ)
    {
        std::cout << "network end EV_READ" << std::endl;
    }
    if (r & EV_WRITE)
    {
        std::cout << "network end EV_WRITE" << std::endl;
    }*/
}

void Network::Write(evutil_socket_t fd, short events, void* arg)
{
    ConnectionMap[std::to_string(fd)]->WriteData();
    //m_users[fd].WriteData();
}

bool Network::Read(int fd)
{
    std::cout << "read clientfd:" << fd << std::endl;
    RemoveSelectFd(ServerBroker::m_fdRead, fd);
    ConnectionMap[std::to_string(fd)]->ReadData();
    //m_users[fd].ReadData();
    /*std::future<bool> result = m_pool->enqueue(std::bind(&ServerBroker::ReadData, &m_users[fd]));
    if (result.get())
    {
        std::cout << "read success" << std::endl;
    }*/
    return true;
}

bool Network::Write(int fd)
{
    
    RemoveSelectFd(ServerBroker::m_fdWrite, fd);
    std::cout << "write\n" << std::endl;
    ConnectionMap[std::to_string(fd)]->WriteData();
    //m_users[fd].WriteData();
    /*std::future<bool> result = m_pool->enqueue(std::bind(&ServerBroker::WriteData, &m_users[fd]));
    if (result.get())
    {
        std::cout << "write success" << std::endl;
    }*/
    return true;
}

bool Network::Close()
{
    //    close(epollfd);
    //    close(listenfd);
    //    delete[] users;
    //    delete  pool;
#ifdef WIN32
    closesocket(m_listenFd);
#else
    close(m_listenFd);
    close(m_epollFd);
#endif
    delete[] m_users;
    delete m_pool;

    return true;
}
