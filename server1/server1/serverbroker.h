#ifndef SERVERBROKER_H
#define SERVERBROKER_H

#ifdef WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#endif  //WIN32

#include <atomic>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <openssl/ssl.h>
#include <event2/event.h>

class Http;
class Database;
class Cryptogram;
class LOGGER;

struct UserMessage
{
	std::string token = "";
	std::string ip = "";
	std::string account = "";
	int visitNumber = 0;
	std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
	std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
};

class ServerBroker 
{
public:
	ServerBroker();
	~ServerBroker();

	//初始化用客户端文件描述符服务器代理
	void Init(int sockfd, const sockaddr_in& address, SSL_CTX** ctx);

	//
	void SetEvent(struct event *event, void (*readfun)(evutil_socket_t, short, void*), void (*writefun)(evutil_socket_t, short, void*));

	//关闭与客户端的连接
	void CloseConnection();

	//读取客户端发送过来的数据
	bool ReadData();

	//向客户端发送数据
	bool WriteData();


	
public:   //全局变量
	static fd_set m_fdWrite;												//windows下使用select监听需要写的文件描述符
	static fd_set m_fdRead;													//windows下使用select监听需要读的文件描述符
	static fd_set m_fdException;											//windows下使用select监听带外数据的文件描述符
	static int m_epollFd;													//Linux下使用 epoll 的监听描述符
	static struct event_base* m_base;
	static std::atomic<int> m_userCount;									//统计当前用户连接数量
	static std::unordered_map<std::string, UserMessage> m_accounts;			//保存当前已登录 token 对应的用户信息
	static std::unordered_map<std::string, std::string> m_logAccounts;		//保存当前已登录的帐号和对应的 token
	static std::unordered_map<std::string, std::chrono::time_point<std::chrono::steady_clock>> m_restrictIp;	//由于频繁访问被禁的IP

private:
	//
	void ModeEvent(short event);

	//对用户的的请求进行分类
	bool Worker();					

	//处理用户的get请求
	bool ProcessGet();

	//处理用户的post请求
	bool ProcessPost();

	//处理用户的登录请求
	bool Login();

	//处理用户的注册请求
	bool Register();

	//处理用户退出系统
	bool Exit();

	//处理用户上传文件的请求
	bool UpFile();

	//处理用户查看文件的请求
	bool DownFile();

	//处理用户获取已上传文件列表的请求
	bool AcquireFiles();

	//
	bool AccessRestrict(std::string& jwt);


private:
	Http* m_http = nullptr;					//http数据处理对象
	Database* m_database = nullptr;			//数据库操作对象
	Cryptogram* m_cryptogram = nullptr;		//数据保密对象
	int m_socketFd;							//客户端文件描述符
	sockaddr_in m_address;					//存储客户端套接字信息

	LOGGER *m_logger;
	SSL* m_ssl = nullptr;
	struct event* m_event = nullptr;
	void (*m_readfun)(evutil_socket_t, short, void*);
	void (*m_writefun)(evutil_socket_t, short, void*);
	
};
typedef std::shared_ptr<ServerBroker > ServerBrokerPtr;
#endif //SERVERBROKER_H